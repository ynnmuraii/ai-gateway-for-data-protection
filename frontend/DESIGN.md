---
name: Контур
description: Тёмная минималистичная панель локального AI-шлюза.
colors:
  ink: "#ececec"
  muted: "#a6a6a6"
  faint: "#8c8c8c"
  ground: "#212121"
  sidebar: "#171717"
  surface: "#262626"
  hover: "#303030"
  line: "#3a3a3a"
  primary: "#ececec"
  primary-ink: "#1b1b1b"
  danger: "#f4a7a7"
  control: "#2b2b2b"
  control-border: "#535353"
  white: "#fff"
  focus: "#c5d6ff"
  allow-ink: "#b5cff7"
  allow-surface: "#283545"
  mask-ink: "#a7d5b8"
  mask-surface: "#293a31"
  block-ink: "#f1b1b1"
  block-surface: "#422b2b"
typography:
  headline:
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-.025em"
  title:
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: 'ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontSize: "13px"
    fontWeight: 500
    lineHeight: 1.5
  button:
    fontSize: "14px"
    fontWeight: 500
    lineHeight: 1.4
  badge:
    fontSize: "11px"
    fontWeight: 500
    lineHeight: 1.5
  code:
    fontFamily: 'ui-monospace, "Cascadia Mono", "SFMono-Regular", Consolas, monospace'
rounded:
  badge: "6px"
  field: "8px"
  button: "9px"
  panel: "12px"
  dialog: "16px"
spacing:
  compact: "8px"
  small: "12px"
  medium: "16px"
  section: "24px"
  page: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "9px 14px"
  button-primary-hover:
    backgroundColor: "{colors.white}"
  button-secondary:
    backgroundColor: "{colors.control}"
    textColor: "{colors.ink}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "9px 14px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "#c5c5c5"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "7px 9px"
  button-danger:
    backgroundColor: "transparent"
    textColor: "{colors.danger}"
    typography: "{typography.button}"
    rounded: "{rounded.button}"
    padding: "9px 14px"
  input:
    backgroundColor: "{colors.control}"
    textColor: "{colors.ink}"
    typography: "{typography.body}"
    rounded: "{rounded.field}"
    padding: "9px 11px"
  panel:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.panel}"
    padding: "22px"
  badge-mask:
    backgroundColor: "{colors.mask-surface}"
    textColor: "{colors.mask-ink}"
    typography: "{typography.badge}"
    rounded: "{rounded.badge}"
    padding: "3px 8px"
---

# Design System: Контур

## Overview

**Creative North Star: "Тёмный минимализм Open WebUI / Ollama"**

Сдержанный графитовый интерфейс «Контура» следует выбранному пользователем направлению Open WebUI и Ollama. Иерархию создают тональные поверхности, компактная системная типографика и светлые основные действия.

Плотность рассчитана на повседневную настройку и проверку данных. Текст краткий, иконки помогают навигации, а цвет сообщает состояние.

**Key Characteristics:**

- Графитовые поверхности без теней.
- Светлые основные действия и нейтральная навигация.
- Нативные поля и диалоги, видимый клавиатурный фокус.
- Короткие переходы с поддержкой reduced motion.

## Colors

### Primary

Светлый primary выделяет основное действие; primary-ink обеспечивает тёмную надпись. Белый используется при наведении.

### Neutral

Sidebar отделяет навигацию, ground служит фоном работы, surface объединяет содержимое панели. Ink, muted и faint задают уровни текста; line и control-border обозначают разделители и границы полей.

ALLOW, MASK и BLOCK используют соответствующие пары ink/surface из frontmatter. Черновики и публикации нейтральны; работоспособность, ошибки и предупреждения получают локальный цвет состояния из текущего CSS.

**The State Color Rule.** Цветовые акценты сообщают решение, работоспособность, ошибку или предупреждение; обычные действия остаются нейтральными.

## Typography

Системный sans применяется во всём интерфейсе, без внешней загрузки шрифтов. Headline соответствует заголовку страницы, title — панели, body — основному тексту, label — подписи поля. Роли наследуют семейство body; отдельного display-шрифта нет.

Вспомогательный текст и таблицы компактны (12px); подзаголовки — полужирные (14px). Значения метрик крупнее (28px, 500), на мобильном — 25px. Таблицы, числовые поля и метрики используют табличные цифры. Code предназначен для идентификаторов и технического вывода. Максимальная длина абзаца — 72ch.

## Layout

Десктопная оболочка: боковая навигация (232px), рабочая область с заголовком (минимум 74px) и контейнером содержимого (максимум 1450px, отступы 28px 32px). Двухколоночные рабочие группы имеют промежуток 24px; панели — внутренний отступ 22px. Таблицы прокручиваются внутри своей обёртки.

- До 1100px: навигация сужается до 208px, внешние отступы — до 24px; четыре поля перестраиваются в две колонки.
- До 850px: парные панели и редакторы складываются вертикально; метрики остаются в двух колонках, список версий занимает две колонки.
- До 700px: навигация выезжает слева по кнопке меню, ширина — 232px. Содержимое получает отступы 20px 16px, панели — 18px; заголовок уменьшается до 19px, его область — минимум 66px.
- При coarse pointer элементы управления имеют минимум 44px, поля — шрифт 16px. Минимальная ширина страницы — 320px.

## Elevation & Depth

Теней нет. Глубину создаёт различие нейтральных поверхностей и тонкие границы элементов управления. Нативный модальный диалог располагается поверх содержимого с затемнением backdrop (#0009); мобильная навигация использует отдельное затемнение (#0008).

## Shapes

Мягкие прямоугольные углы следуют шкале rounded: самые компактные у бейджей, более свободные у панелей и диалогов. Границы полей и вторичных кнопок тонкие (1px). Круглая форма используется у аватара, индикатора состояния и загрузчика.

## Components

- **Buttons:** основной светлый, вторичный тонально отделён с границей, текстовый прозрачен, опасный выделяет действие красным текстом и границей. Минимальная высота — 38px; квадратная иконка-кнопка — 36px. Disabled имеет opacity .45.
- **Inputs / Fields:** нативные input, select, textarea и checkbox. Подпись связана с полем, подсказка — через aria-describedby. При наведении граница светлеет; выключенное поле сохраняет читаемую подпись.
- **Cards / Containers:** ровная тональная поверхность без тени; заголовок и действия располагаются в одной строке, содержимое начинается ниже.
- **Navigation:** иконка и короткая подпись; активный пункт получает светлее фон и белый текст. Контурные SVG используют stroke 1.6, закруглённые окончания и соединения; обычный размер — 20px. Мобильное меню закрывается выбором пункта, затемнением или Escape.
- **Badges:** компактная текстовая метка решения, без интерактивного состояния. Цвет дополняет подпись. Статусы версий нейтральны.
- **Dialogs:** нативный dialog вызывается через showModal; Escape и кнопка закрывают окно, фокус возвращается к предыдущему элементу. Ширина — не более 700px с адаптивным запасом до краёв; длинное содержимое прокручивается внутри.
- **Feedback:** ошибка выводится через alert, загрузка и уведомление — через status. Пустые состояния кратко описывают отсутствие данных.
- **Focus / Motion:** клавиатурный фокус — контур 2px цвета focus с отступом 3px. Переходы цвета и границы длятся 160ms; мобильная навигация — 180ms ease-out. Загрузчик вращается за 700ms. При prefers-reduced-motion все переходы и анимации отключены; forced colors добавляет различимые границы.

## Do's and Don'ts

- **Do** сохранять системный шрифт, тональные поверхности и краткие русские подписи.
- **Do** сопровождать цвет состояния текстом и сохранять видимый фокус.
- **Do** использовать нативные поля, подтверждение опасных действий и адаптивную компоновку.

- **Don't** добавлять декоративные акценты, градиенты, иллюстрации и маркетинговые блоки.
- **Don't** придавать метрикам и обычным действиям цвет состояния.
- **Don't** скрывать действия на узком экране или включать анимацию при reduced motion.
