# data/

`eval_*.jsonl` — размеченные вручную уникальные команды из реальных логов Cowrie (поля: `command`, `label`, `count` — сколько раз встретилась, `sample` — из какой страты выборка).
Исходные дампы не включены (у GitHub-репозиториев нет лицензии на перераспределение; дамп CyberLab — Zenodo 10.5281/zenodo.3687527, IP в нём захэшированы).
Команды — текст, введённый атакующими; **не выполняйте их**. Подробности разметки и ограничения — в `../EVALUATION.md`.

* `eval_cyberlab_seen.jsonl` — автор видел эти команды до написания правил (не независимая выборка).
* `eval_real_round1..4.jsonl` — слепые выборки раундов 1–4 (независимы только в момент первого запуска каждого раунда).

* `real_suspected_humans.json` — id реальной сессии, которая при ручном просмотре похожа на человека (исключена из «ботов» при обучении is_human).
* `real_bot_sessions.jsonl.gz` — **не включён** (производная от логов без лицензии на распространение). Собрать: `python scripts/extract_sessions.py data/real_bot_sessions.jsonl.gz <логи Cowrie>`.
  Использованные логи: репозитории `Cowrie_Honeypot_Log_Analysis_Engine` (logs/*.json) и `cowrie-honeypot` (logs/cowrie.json*) с GitHub.
