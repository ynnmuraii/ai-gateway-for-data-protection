/** Actual GUI test. Authentication data and raw message bodies never enter logs. */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { chromium } = require('../.runtime/browser-tools/node_modules/playwright');

const root = path.resolve(__dirname, '..');
const access = JSON.parse(fs.readFileSync(path.join(root, '.runtime/compose-access.json'), 'utf8'));
const screenshot = path.join(root, '.runtime/openwebui-chat.png');
const reportPath = path.join(root, 'docs/openwebui-browser-review.md');
const origin = 'http://localhost:3000';
const modelLabel = 'Gateway simulator (no LLM)';
const sampleEmail = 'qa.synthetic@example.com';
const prompt = `Помоги составить короткое деловое письмо: отправь итоговый отчёт на ${sampleEmail}. Напомни, что команда должна проверить результаты за неделю и согласовать следующую встречу. Сохрани спокойный и понятный тон, а адрес получателя используй только в строке контакта.`;
const checks = [];
const wire = [];
const consoleErrors = [];
const pageErrors = [];
const failedResponses = [];
const expectedDiscoveryPaths = new Set(['/api/v1/tools/','/api/v1/functions/','/api/v1/terminals/','/ollama/api/version']);
const socketEvidence = {email:{completionEvents:0,deltaEvents:0},followup:{completionEvents:0,deltaEvents:0},jwt:{completionEvents:0,deltaEvents:0}};
let stage = 'start';
let regularUser = false;

function typeOf(value) {return value===null?'null':Array.isArray(value)?'array':typeof value;}
function fields(value) {return value && typeof value==='object' && !Array.isArray(value) ? Object.fromEntries(Object.keys(value).sort().map(key=>[key,typeOf(value[key])])) : {};}
function check(name,passed,detail) {checks.push({name,passed:Boolean(passed),detail});}
function isExpectedDenial(response) {return response.method==='GET' && response.status===403 && expectedDiscoveryPaths.has(response.path);}
function isExpectedConsoleError(error) {
  return (error.stage==='jwt' && error.kind==='policy_blocked') || (error.kind==='resource_load_error' && failedResponses.some(response=>isExpectedDenial(response) && response.path===error.path));
}
function safePath(url) {try {return new URL(url).pathname.replace(/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/gi,'[id]');}catch {return null;}}
function classifyError(text) {
  if (/unsupported[ _]request[ _]field/i.test(text)) return 'unsupported_request_field';
  if (/policy[ _]blocked/i.test(text)) return 'policy_blocked';
  if (/Failed to load resource/i.test(text)) return 'resource_load_error';
  if (/websocket/i.test(text)) return 'websocket_error';
  return 'browser_console_error';
}
function safeResultCodes(text) {
  return ['unsupported_request_field','literal_marker_conflict','detector_failure','detector_timeout','detector_unavailable','policy_blocked','invalid_request'].filter(code=>new RegExp(code.replaceAll('_','[ _]'),'i').test(text));
}
function streamEvidence(value,evidence,depth=0) {
  if (!value || typeof value!=='object' || depth>10) return;
  if (value.type==='chat:completion') evidence.completionEvents++;
  if (Array.isArray(value.choices) && value.choices.some(choice=>typeof choice?.delta?.content==='string' && choice.delta.content.length>0)) evidence.deltaEvents++;
  for (const nested of Object.values(value)) if (nested && typeof nested==='object')streamEvidence(nested,evidence,depth+1);
}
async function startLengthObserver(page) {
  await page.evaluate(()=>{
    window.__gatewaySmokeObserver?.disconnect();
    window.__gatewaySmokeLengths=[];
    window.__gatewaySmokeObserver=new MutationObserver(()=>{
      const nodes=document.querySelectorAll('.chat-assistant');
      const length=nodes[nodes.length-1]?.textContent?.trim().length || 0;
      const lengths=window.__gatewaySmokeLengths;
      if(length>0 && lengths[lengths.length-1]!==length)lengths.push(length);
    });
    window.__gatewaySmokeObserver.observe(document.body,{childList:true,subtree:true,characterData:true});
  });
}
async function sendFromComposer(page,text) {
  const previousAssistants=await page.locator('.chat-assistant').count();
  const previousRegenerateButtons=await page.locator('[aria-label="Перегенерировать"]').count();
  await startLengthObserver(page);
  await page.locator('[contenteditable="true"]').fill(text);
  await page.locator('button[type="submit"]').click();
  await page.waitForFunction(count=>document.querySelectorAll('.chat-assistant').length>count,previousAssistants,{timeout:30000});
  await page.locator('.chat-assistant').last().waitFor({timeout:30000});
  await page.waitForFunction(()=>{
    const nodes=document.querySelectorAll('.chat-assistant');
    return Boolean(nodes[nodes.length-1]?.textContent?.trim());
  },null,{timeout:30000});
  await page.waitForFunction(count=>document.querySelectorAll('[aria-label="Перегенерировать"]').length>count,previousRegenerateButtons,{timeout:30000});
  await page.waitForTimeout(150);
  return {text:await page.locator('.chat-assistant').last().innerText(),lengths:await page.evaluate(()=>window.__gatewaySmokeLengths || [])};
}
function writeReport(outcome,failure) {
  const rows=checks.map(item=>`| ${item.passed?'PASS':'FAIL'} | ${item.name} | ${item.detail || '—'} |`).join('\n');
  const failed=checks.filter(item=>!item.passed);
  const lines=[
    '# Actual Open WebUI browser review',
    '',
    `Checked ${new Date().toISOString()} using a fresh Playwright Chrome context against \`${origin}\`. Result: **${outcome}**.`,
    '',
    'The test signs in through the normal login form as the provisioned regular user, selects **Gateway simulator (no LLM)**, types a natural Russian prompt containing a synthetic email, submits it through the chat composer, inspects the rendered assistant response, sends a follow-up in the same chat, then starts a new chat and submits an independently generated synthetic JWT. It does not craft chat API calls or change application configuration. Credentials, tokens, raw request/response bodies and message values are never printed or written to this report.',
    '',
    '| Result | Acceptance check | Evidence |',
    '| --- | --- | --- |',
    rows || '| FAIL | Browser setup | Did not reach acceptance checks |',
    '',
    `Email streaming evidence: ${socketEvidence.email.completionEvents} chat-completion WebSocket events; ${socketEvidence.email.deltaEvents} nonempty delta events. Only counts and DOM text lengths are retained.`,
    '',
    `Browser console errors: **${consoleErrors.length}**; uncaught page errors: **${pageErrors.length}**. Console classifications: ${consoleErrors.length?consoleErrors.map(item=>item.kind).join(', '):'none'}. Page error names: ${pageErrors.length?pageErrors.map(item=>item.name).join(', '):'none'}.`,
    `Expected disabled-discovery denials: **${failedResponses.filter(isExpectedDenial).length}**; unexpected failed resources: **${failedResponses.filter(response=>!isExpectedDenial(response)).length}**; unexpected console errors: **${consoleErrors.filter(error=>!isExpectedConsoleError(error)).length}**.`,
    `Failed browser resource responses (path/status only): ${JSON.stringify(failedResponses)}.`,
    '',
    'Known limitation: Open WebUI probes disabled tool, function, terminal and Ollama discovery paths. The installation deliberately denies GET requests to `/api/v1/tools/`, `/api/v1/functions/`, `/api/v1/terminals/` and `/ollama/api/version` with HTTP 403, producing browser console resource warnings. The test permits only this exact path/method/status list and reports the denials separately. Any other failed resource, unrelated console error or uncaught JavaScript error fails acceptance. The proxy/backend denials remain in force.',
    '',
    'Screenshot: `.runtime/openwebui-chat.png` (synthetic email chat only; no login credentials). The original synthetic prompt can appear in the user message; acceptance requires its email to be absent from the assistant output. The model explicitly identifies itself as a simulator without LLM inference.',
    '',
    '## Safe browser request metadata',
    '',
    'The browser sends Open WebUI’s own UI envelope to `POST /api/chat/completions`; Open WebUI constructs its provider request on the server. The metadata below lists field names/types only and does not imply that this same envelope is forwarded to the gateway.',
    '',
    '```json',
    JSON.stringify(wire,null,2),
    '```',
    '',
    ...(failure?[`The run stopped at stage \`${failure.stage}\` with \`${failure.name}\`. Raw exception text is omitted.`, '']:[]),
    failed.length?`Failed checks: ${failed.map(item=>item.name).join('; ')}. The smoke script exits unsuccessfully until these pass.`:'All actual-GUI acceptance checks passed.',
    '',
  ];
  fs.writeFileSync(reportPath,lines.join('\n'));
}

(async()=>{
  const browser=await chromium.launch({channel:'chrome',headless:true});
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  const page=await context.newPage();
  let failure;
  page.on('console',message=>{if(message.type()==='error')consoleErrors.push({stage,kind:classifyError(message.text()),path:safePath(message.location().url)});});
  page.on('pageerror',error=>pageErrors.push({stage,name:error.name}));
  page.on('request',request=>{
    if(new URL(request.url()).pathname!=='/api/chat/completions')return;
    try {
      const body=request.postDataJSON();
      wire.push({case:stage,fields:fields(body),nestedFields:Object.fromEntries(['params','features','chat_variables','variables','user_message','model_item','background_tasks'].map(key=>[key,fields(body[key])])),stream:body.stream===true});
    } catch {wire.push({case:stage,parse:'not-json'});}
  });
  page.on('response',async response=>{
    const pathname=new URL(response.url()).pathname;
    if(response.status()>=400)failedResponses.push({stage,method:response.request().method(),status:response.status(),path:safePath(response.url())});
    if(pathname==='/api/chat/completions') {
      const current=wire[wire.length-1];if(current)current.httpStatus=response.status();
    }
    if(pathname==='/api/v1/auths/signin' && response.ok()) {
      try {const body=await response.json();regularUser=body.role==='user';}catch { /* Never log authentication responses. */ }
    }
  });
  page.on('websocket',socket=>socket.on('framereceived',frame=>{
    if(typeof frame.payload!=='string'||!frame.payload.startsWith('42'))return;
    try {
      const packet=JSON.parse(frame.payload.slice(frame.payload.indexOf('[')));
      if(packet[0]==='events' && socketEvidence[stage])streamEvidence(packet[1],socketEvidence[stage]);
    } catch { /* Socket pings and other events are not acceptance evidence. */ }
  }));
  try {
    stage='login';
    await page.goto(origin,{waitUntil:'domcontentloaded'});
    await page.locator('input[type="email"]').waitFor({timeout:30000});
    await page.locator('input[type="email"]').fill(access.webui_user_email);
    await page.locator('input[type="password"]').fill(access.webui_user_password);
    await page.locator('button[type="submit"]').click();
    await page.locator('input[type="password"]').waitFor({state:'hidden',timeout:30000});
    await page.getByRole('button',{name:'Выбранная модель: '+modelLabel,exact:true}).waitFor({timeout:30000});
    check('Regular-user login through GUI',regularUser,'Role from the normal sign-in response is user; auth data is not retained.');
    stage='model';
    await page.getByRole('button',{name:'Выбранная модель: '+modelLabel,exact:true}).click();
    await page.locator('[aria-label="Выбрать модель '+modelLabel+'"]').click();
    check('Select the disclosed simulator model',await page.getByRole('button',{name:'Выбранная модель: '+modelLabel,exact:true}).isVisible(),'Selected model label includes no LLM.');
    stage='email';
    const emailResult=await sendFromComposer(page,prompt);
    const hasMask=/\[EMAIL_[A-Z2-7]{52}\]/.test(emailResult.text);
    const unsupported=/unsupported[ _]request[ _]field/i.test(emailResult.text);
    check('Natural prompt produces a masked assistant response',hasMask,'Assistant contains a deterministic EMAIL pseudonym marker.');
    check('Raw synthetic email absent from assistant output',!emailResult.text.includes(sampleEmail),'Checks only the assistant container.');
    check('Assistant identifies simulator output',/Демонстрационный провайдер \(без LLM\)/.test(emailResult.text),'No claim of real LLM inference.');
    check('Streamed assistant response through GUI',wire.some(item=>item.case==='email'&&item.stream)&&hasMask&&(socketEvidence.email.deltaEvents>1||emailResult.lengths.length>1),`Distinct nonempty rendered lengths: ${emailResult.lengths.length}; delta events: ${socketEvidence.email.deltaEvents}.`);
    check('No unsupported-field error for email GUI request',!unsupported,unsupported?'Assistant shows unsupported_request_field.':'Real GUI request accepted.');
    await page.screenshot({path:screenshot,fullPage:true});
    stage='followup';
    const followup=await sendFromComposer(page,'Объясни подробнее, как оформить такой отчёт и выбрать спокойный тон письма.');
    const followupCodes=safeResultCodes(followup.text);
    check('Same-chat follow-up succeeds with prior masked assistant history',/Демонстрационный провайдер \(без LLM\)/.test(followup.text)&&followupCodes.length===0,followupCodes.length?'Safe assistant result codes: '+followupCodes.join(', '):'Existing masked history accepted.');
    check('Follow-up assistant response contains no raw email',!followup.text.includes(sampleEmail),'Original synthetic email remains absent from provider output.');
    stage='new-chat-click';
    await page.locator('[aria-label="Новый чат"]:visible').first().click();
    stage='new-chat-ready';
    await page.waitForFunction(()=>document.querySelectorAll('.chat-assistant').length===0,null,{timeout:15000});
    const header=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT'})).toString('base64url');
    const payload=Buffer.from(JSON.stringify({sub:'synthetic-openwebui-browser-case'})).toString('base64url');
    const signed=header+'.'+payload;
    const syntheticJwt=signed+'.'+crypto.createHmac('sha256','synthetic-test-not-authentication').update(signed).digest('base64url');
    stage='jwt';
    const jwtResult=await sendFromComposer(page,'Это синтетический тест. Проверь строку токена: '+syntheticJwt);
    const blocked=/policy[ _]blocked|заблокир/i.test(jwtResult.text);
    check('New-chat synthetic JWT is blocked with a safe error',blocked,blocked?'Assistant displays policy_blocked.':'Expected policy_blocked absent.');
    check('Blocked assistant response contains no raw JWT',!jwtResult.text.includes(syntheticJwt),'No token is echoed in the assistant error.');
    check('Blocked request produces no simulator answer',!/Демонстрационный провайдер \(без LLM\)/.test(jwtResult.text),'No provider output is rendered.');
    check('No unsupported-field error for JWT GUI request',!/unsupported[ _]request[ _]field/i.test(jwtResult.text),'Policy decision is reachable from a genuine new-chat envelope.');
    check('No uncaught browser errors',pageErrors.length===0,`${pageErrors.length} uncaught page errors.`);
    check('Only deliberately denied discovery resources fail',failedResponses.every(isExpectedDenial),`${failedResponses.filter(isExpectedDenial).length} exact known GET/403 discovery denials; ${failedResponses.filter(response=>!isExpectedDenial(response)).length} unexpected resource failures.`);
    check('No unexpected browser console errors',consoleErrors.every(isExpectedConsoleError),`${consoleErrors.length} console resource errors; ${consoleErrors.filter(error=>!isExpectedConsoleError(error)).length} unexpected errors.`);
  } catch(error) {
    failure={stage,name:error.name};
    check('Browser workflow completed',false,`Stopped at ${stage}; ${error.name}.`);
  } finally {
    await context.close();
    await browser.close();
  }
  const passed=!failure&&checks.every(item=>item.passed);
  writeReport(passed?'PASS':'FAIL',failure);
  console.log(JSON.stringify({result:passed?'PASS':'FAIL',checks:checks.length,failedChecks:checks.filter(item=>!item.passed).map(item=>item.name),consoleErrors:consoleErrors.length,pageErrors:pageErrors.length,failedResponses,requestMetadata:wire}));
  if(!passed)process.exitCode=1;
})().catch(error=>{
  const failure={stage,name:error.name};
  writeReport('FAIL',failure);
  console.error(JSON.stringify({result:'FAIL',stage,name:error.name}));
  process.exitCode=1;
});
