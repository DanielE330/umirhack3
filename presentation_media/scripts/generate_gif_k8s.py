import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
frames = []

font_mono = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 20)
font_bold = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 20)
font_ui = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 16)
font_alert = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 22)

def create_base_terminal():
    img = Image.new('RGB', (W, H), '#130f0c')
    draw = ImageDraw.Draw(img)
    
    # Outer terminal window
    draw.rounded_rectangle([(30, 20), (W - 30, H - 20)], radius=12, fill='#19130f', outline='#2d221a', width=2)
    # Header bar
    draw.rounded_rectangle([(30, 20), (W - 30, 65)], radius=12, fill='#231a14')
    draw.rectangle([(30, 50), (W - 30, 65)], fill='#231a14')
    
    # Window buttons
    draw.ellipse([(50, 36), (62, 48)], fill='#ef4444')
    draw.ellipse([(72, 36), (84, 48)], fill='#f59e0b')
    draw.ellipse([(94, 36), (106, 48)], fill='#22c55e')
    
    draw.text((W // 2, 42), 'kali@attacker-box: ~ (Target: 10.20.0.11:6443 - KubeForge Decoy)', fill='#a8a29e', font=font_ui, anchor='mm')
    return img

scenario_steps = [
    # Step 1: initial prompt
    {"lines": [("kali@attacker-box:~$ ", "#38bdf8", False)], "pause": 600},
    # Step 2: typing kubectl get nodes
    {"lines": [("kali@attacker-box:~$ kubectl get ", "#38bdf8", False)], "pause": 300},
    {"lines": [("kali@attacker-box:~$ kubectl get nodes", "#38bdf8", False)], "pause": 500},
    # Step 3: nodes output
    {"lines": [
        ("kali@attacker-box:~$ kubectl get nodes", "#ffffff", False),
        ("NAME                   STATUS   ROLES           AGE   VERSION", "#f59e0b", False),
        ("k8s-prod-master-01      Ready    control-plane   42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-01      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-02      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ ", "#38bdf8", False)
    ], "pause": 800},
    # Step 4: typing kubectl get secrets
    {"lines": [
        ("kali@attacker-box:~$ kubectl get nodes", "#ffffff", False),
        ("NAME                   STATUS   ROLES           AGE   VERSION", "#f59e0b", False),
        ("k8s-prod-master-01      Ready    control-plane   42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-01      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-02      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ kubectl get secrets -A", "#38bdf8", False)
    ], "pause": 600},
    # Step 5: dump secrets with canary tokens
    {"lines": [
        ("kali@attacker-box:~$ kubectl get nodes", "#ffffff", False),
        ("NAME                   STATUS   ROLES           AGE   VERSION", "#f59e0b", False),
        ("k8s-prod-master-01      Ready    control-plane   42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-01      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-02      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ kubectl get secrets -A", "#ffffff", False),
        ("NAMESPACE     NAME                  TYPE     DATA   CANARY PAYLOAD", "#f59e0b", False),
        ("kube-system   stripe-prod-secret    Opaque   2      stripe_secret_canary_live_99f", "#e7e5e4", False),
        ("default       aws-s3-backup-key     Opaque   3      AKIAIOSFODNN7CANARYX9", "#e7e5e4", False),
        ("prod-db       postgres-superuser    Opaque   1      honey_canary_pass_920x", "#e7e5e4", False),
        ("billing       jwt-signing-secret    Opaque   1      canary_jwt_hs256_seed_3", "#e7e5e4", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ ", "#38bdf8", False)
    ], "pause": 1000},
    # Step 6: HoneyForge Detection Overlay
    {"lines": [
        ("kali@attacker-box:~$ kubectl get nodes", "#ffffff", False),
        ("NAME                   STATUS   ROLES           AGE   VERSION", "#f59e0b", False),
        ("k8s-prod-master-01      Ready    control-plane   42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-01      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("k8s-prod-worker-02      Ready    <none>          42d   v1.28.3", "#22c55e", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ kubectl get secrets -A", "#ffffff", False),
        ("NAMESPACE     NAME                  TYPE     DATA   CANARY PAYLOAD", "#f59e0b", False),
        ("kube-system   stripe-prod-secret    Opaque   2      stripe_secret_canary_live_99f", "#e7e5e4", False),
        ("default       aws-s3-backup-key     Opaque   3      AKIAIOSFODNN7CANARYX9", "#e7e5e4", False),
        ("prod-db       postgres-superuser    Opaque   1      honey_canary_pass_920x", "#e7e5e4", False),
        ("billing       jwt-signing-secret    Opaque   1      canary_jwt_hs256_seed_3", "#e7e5e4", False),
        ("", "#ffffff", False),
        ("kali@attacker-box:~$ # Canary Token Exfiltrated by Attacker!", "#ef4444", False)
    ], "alert": True, "pause": 2500}
]

for step in scenario_steps:
    img = create_base_terminal()
    draw = ImageDraw.Draw(img)
    
    y = 85
    for line in step["lines"]:
        draw.text((55, y), line[0], fill=line[1], font=font_mono)
        y += 28
        
    if step.get("alert"):
        # Draw sleek detection banner
        draw.rounded_rectangle([(70, H - 180), (W - 70, H - 45)], radius=10, fill='#20100d', outline='#ef4444', width=3)
        draw.text((W // 2, H - 150), '[!] HONEYFORGE ALERT: CANARY TOKEN EXFILTRATION DETECTED', fill='#ef4444', font=font_alert, anchor='mm')
        draw.text((W // 2, H - 118), 'HoneyMind Threat Score: 98.4/100 | Decoy: KubeForge (vmbr1:6443)', fill='#f59e0b', font=font_mono, anchor='mm')
        draw.text((W // 2, H - 85), 'Action: Forensic ZFS snapshot created | SOC Telegram notified in 12ms', fill='#22c55e', font=font_mono, anchor='mm')
    
    # Add frame
    # Convert to P mode for GIF with adaptive palette
    frame_p = img.convert('P', palette=Image.ADAPTIVE)
    frames.append((frame_p, step["pause"]))

# Save animated GIF
out_path = r'c:\Progects\HoneyForge\presentation_media\gif_k8s_attack.gif'
images = [f[0] for f in frames]
durations = [f[1] for f in frames]

images[0].save(
    out_path,
    save_all=True,
    append_images=images[1:],
    duration=durations,
    loop=0,
    optimize=True
)
print('gif_k8s_attack.gif generated successfully!')
