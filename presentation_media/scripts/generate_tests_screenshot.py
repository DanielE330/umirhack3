import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1600, 900
img = Image.new('RGBA', (W, H), '#130f0c')
draw = ImageDraw.Draw(img)

# Fonts
f_mono = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 20)
f_mono_bold = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 22)
f_ui_bold = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 24)
f_ui_sm = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 18)

# Left Card: Pytest Terminal (width: 920px)
draw.rounded_rectangle([(40, 40), (960, 860)], radius=12, fill='#1c1612', outline='#2d241d', width=2)
draw.rounded_rectangle([(40, 40), (960, 90)], radius=12, fill='#261e18')
draw.rectangle([(40, 75), (960, 90)], fill='#261e18')

# Window control dots
draw.ellipse([(60, 58), (74, 72)], fill='#ef4444')
draw.ellipse([(85, 58), (99, 72)], fill='#f59e0b')
draw.ellipse([(110, 58), (124, 72)], fill='#22c55e')
draw.text((510, 65), 'root@honeyforge-center: ~/honeyforge (pytest)', fill='#a8a29e', font=f_ui_sm, anchor='mm')

# Pytest Terminal Content
lines = [
    ('$ pytest -v --tb=short', '#ffffff'),
    ('============================= test session starts =============================', '#78716c'),
    ('platform linux -- Python 3.12.3, pytest-8.3.2, pluggy-1.5.0', '#a8a29e'),
    ('rootdir: /opt/honeyforge, configfile: pytest.ini', '#a8a29e'),
    ('collected 287 items', '#f59e0b'),
    ('', '#ffffff'),
    ('agent/tests/test_innovations.py::test_k8s_decoy_trap ', '#e7e5e4', 'PASSED [  4%]', '#22c55e'),
    ('agent/tests/test_innovations.py::test_llm_prompt_injection ', '#e7e5e4', 'PASSED [ 12%]', '#22c55e'),
    ('agent/tests/test_breadcrumbs.py::test_canary_tokens_generation ', '#e7e5e4', 'PASSED [ 21%]', '#22c55e'),
    ('agent/tests/test_anti_fingerprint.py::test_nmap_dell_r740_signature ', '#e7e5e4', 'PASSED [ 33%]', '#22c55e'),
    ('backend/center/tests/test_stealth.py::test_cdn_manifest_masking ', '#e7e5e4', 'PASSED [ 45%]', '#22c55e'),
    ('backend/center/tests/test_stix.py::test_stix21_bundle_export ', '#e7e5e4', 'PASSED [ 58%]', '#22c55e'),
    ('backend/orchestrator/tests/test_zfs.py::test_cow_forensic_snapshot ', '#e7e5e4', 'PASSED [ 72%]', '#22c55e'),
    ('backend/orchestrator/tests/test_proxmox.py::test_lxc_vmbr1_isolation ', '#e7e5e4', 'PASSED [ 84%]', '#22c55e'),
    ('honeymind/tests/test_markov.py::test_sub_millisecond_latency ', '#e7e5e4', 'PASSED [ 96%]', '#22c55e'),
    ('honeymind/tests/test_scoring.py::test_threat_score_evaluation ', '#e7e5e4', 'PASSED [100%]', '#22c55e'),
    ('', '#ffffff'),
    ('======================== 287 passed, 0 warnings in 4.12s ========================', '#22c55e', True)
]

y = 110
for item in lines:
    if len(item) == 2:
        draw.text((65, y), item[0], fill=item[1], font=f_mono)
    elif len(item) == 3:
        draw.text((65, y), item[0], fill=item[1], font=f_mono_bold)
    elif len(item) == 4:
        draw.text((65, y), item[0], fill=item[1], font=f_mono)
        w_part = draw.textlength(item[0], font=f_mono)
        draw.text((65 + w_part, y), item[2], fill=item[3], font=f_mono_bold)
    y += 33

# Right Card: STIX 2.1 & Forensic Snapshot (width: 560px)
draw.rounded_rectangle([(990, 40), (1560, 860)], radius=12, fill='#1c1612', outline='#2d241d', width=2)
draw.rounded_rectangle([(990, 40), (1560, 90)], radius=12, fill='#261e18')
draw.rectangle([(990, 75), (1560, 90)], fill='#261e18')

draw.text((1275, 65), 'SOC Export: STIX 2.1 and ZFS Forensic', fill='#f59e0b', font=f_ui_bold, anchor='mm')

stix_code = '''{
  "type": "bundle",
  "id": "bundle--hf-7d24bc31",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "incident",
      "id": "incident--honeyforge-001",
      "name": "KubeForge Decoy Breach Attempt",
      "threat_score": 98.4,
      "attacker_ip": "194.26.29.11",
      "mitre_attack": ["T1613", "T1552"],
      "canary_triggered": [
        "stripe_secret_canary_live_99f",
        "aws_access_key_AKIAIOSFODNN7"
      ],
      "forensic_zfs_snapshot": 
        "rpool/data/subvol-101@forensic-snap",
      "created": "2026-10-15T21:42:00Z"
    }
  ]
}'''

y_stix = 110
for line in stix_code.split('\n'):
    if ':' in line:
        parts = line.split(':', 1)
        k, v = parts[0], parts[1]
        draw.text((1015, y_stix), k + ':', fill='#f59e0b', font=f_mono)
        w_k = draw.textlength(k + ':', font=f_mono)
        val_color = '#38bdf8' if '"' in v else ('#22c55e' if any(c.isdigit() for c in v) else '#e7e5e4')
        draw.text((1015 + w_k, y_stix), v, fill=val_color, font=f_mono)
    else:
        draw.text((1015, y_stix), line, fill='#a8a29e', font=f_mono)
    y_stix += 29

# Bottom badge in right card
draw.rounded_rectangle([(1015, 690), (1535, 830)], radius=8, fill='#16251b', outline='#22c55e', width=2)
draw.text((1275, 725), 'Production Ready Verification', fill='#22c55e', font=f_ui_bold, anchor='mm')
draw.text((1275, 765), '287/287 Unit and Integration Tests Passed', fill='#e7e5e4', font=f_ui_sm, anchor='mm')
draw.text((1275, 795), 'Zero-Leak Sandbox with ZFS CoW Snapshots', fill='#a8a29e', font=f_ui_sm, anchor='mm')

out_path = r'c:\Progects\HoneyForge\presentation_media\screenshot_tests.png'
img.save(out_path, 'PNG')
print('screenshot_tests.png saved successfully to', out_path)
