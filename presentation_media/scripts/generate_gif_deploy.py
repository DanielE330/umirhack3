import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1000, 600
frames = []

font_ui_bold = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 22)
font_ui = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 16)
font_mono = ImageFont.truetype('C:/Windows/Fonts/consola.ttf', 17)
font_btn = ImageFont.truetype('C:/Windows/Fonts/segoeui.ttf', 18)

def draw_deploy_frame(btn_clicked, progress_pct, step_text, finished=False):
    img = Image.new('RGB', (W, H), '#130f0c')
    draw = ImageDraw.Draw(img)
    
    # Backdrop overlay
    # Modal dialog
    mx1, my1, mx2, my2 = 60, 40, W - 60, H - 40
    draw.rounded_rectangle([(mx1, my1), (mx2, my2)], radius=14, fill='#1b1410', outline='#3a2a1f', width=2)
    
    # Modal Header
    draw.rounded_rectangle([(mx1, my1), (mx2, my1 + 65)], radius=14, fill='#251b14')
    draw.rectangle([(mx1, my1 + 40), (mx2, my1 + 65)], fill='#251b14')
    
    draw.text((mx1 + 30, my1 + 32), '⚡ 1-Click Deploy: Развертывание ловушки в Proxmox VE', fill='#f59e0b', font=font_ui_bold, anchor='lm')
    draw.text((mx2 - 30, my1 + 32), '✕', fill='#78716c', font=font_ui_bold, anchor='rm')
    
    # Form fields
    y = my1 + 95
    draw.text((mx1 + 35, y), 'Конфигурация ловушки:', fill='#a8a29e', font=font_ui)
    draw.rounded_rectangle([(mx1 + 35, y + 25), (mx2 - 35, y + 65)], radius=6, fill='#120d0a', outline='#443327')
    draw.text((mx1 + 50, y + 45), 'Профиль: Medium-High KubeForge + Fake-SSH (dmz-vmbr1)', fill='#e7e5e4', font=font_mono, anchor='lm')
    
    y += 85
    draw.text((mx1 + 35, y), 'Целевая среда:', fill='#a8a29e', font=font_ui)
    draw.rounded_rectangle([(mx1 + 35, y + 25), (mx2 - 35, y + 65)], radius=6, fill='#120d0a', outline='#443327')
    draw.text((mx1 + 50, y + 45), 'Гипервизор: pve-node-01 (Proxmox 8.2 ZFS Pool / Isolated DMZ)', fill='#e7e5e4', font=font_mono, anchor='lm')
    
    # Deploy progress box
    y += 95
    draw.rounded_rectangle([(mx1 + 35, y), (mx2 - 35, y + 105)], radius=8, fill='#140e0b', outline='#2d2017')
    
    # Progress text
    draw.text((mx1 + 50, y + 25), step_text, fill='#38bdf8' if not finished else '#22c55e', font=font_mono)
    draw.text((mx2 - 50, y + 25), f'{progress_pct}%', fill='#f59e0b' if not finished else '#22c55e', font=font_mono, anchor='rm')
    
    # Progress bar
    bar_x1, bar_x2 = mx1 + 50, mx2 - 50
    bar_y = y + 65
    draw.line([(bar_x1, bar_y), (bar_x2, bar_y)], fill='#2d2017', width=10)
    if progress_pct > 0:
        fill_x = int(bar_x1 + (bar_x2 - bar_x1) * (progress_pct / 100.0))
        draw.line([(bar_x1, bar_y), (fill_x, bar_y)], fill='#22c55e' if finished else '#f59e0b', width=10)
        
    # Bottom action
    y_btn = my2 - 65
    if not finished:
        if not btn_clicked:
            draw.rounded_rectangle([(mx2 - 270, y_btn), (mx2 - 35, y_btn + 45)], radius=6, fill='#f59e0b')
            draw.text((mx2 - 152, y_btn + 22), '🚀 ЗАПУСТИТЬ ДЕПЛОЙ', fill='#130f0c', font=font_btn, anchor='mm')
        else:
            draw.rounded_rectangle([(mx2 - 270, y_btn), (mx2 - 35, y_btn + 45)], radius=6, fill='#78350f')
            draw.text((mx2 - 152, y_btn + 22), '⏳ РАЗВЕРТЫВАНИЕ...', fill='#fef3c7', font=font_btn, anchor='mm')
    else:
        draw.rounded_rectangle([(mx2 - 320, y_btn), (mx2 - 35, y_btn + 45)], radius=6, fill='#14532d', outline='#22c55e', width=1)
        draw.text((mx2 - 177, y_btn + 22), '✅ ЛОВУШКА В СЕТИ (1.8s)', fill='#86efac', font=font_btn, anchor='mm')
        
    draw.text((mx1 + 35, y_btn + 22), 'HoneyForge Proxmox Orchestrator v2.1', fill='#57534e', font=font_ui, anchor='lm')
    return img

steps = [
    # 0: Modal open, ready to click
    {"clicked": False, "pct": 0, "text": "Ожидание команды оператора...", "fin": False, "pause": 1000},
    # 1: Clicked, cloning template
    {"clicked": True, "pct": 20, "text": "Cloning Proxmox LXC template 9000 (Ubuntu 22.04)...", "fin": False, "pause": 800},
    # 2: Net bridge config
    {"clicked": True, "pct": 50, "text": "Attaching isolated vNIC to vmbr1 (DMZ 10.20.0.14/24)...", "fin": False, "pause": 800},
    # 3: Agent inject
    {"clicked": True, "pct": 80, "text": "Injecting stealth netsvc agent and canary credentials...", "fin": False, "pause": 800},
    # 4: Finished! Online!
    {"clicked": True, "pct": 100, "text": "LXC CT #104 started! Agent connected via CDN manifest.", "fin": True, "pause": 2500}
]

for s in steps:
    im = draw_deploy_frame(s["clicked"], s["pct"], s["text"], s["fin"])
    im_p = im.convert('P', palette=Image.ADAPTIVE)
    frames.append((im_p, s["pause"]))

out_path = r'c:\Progects\HoneyForge\presentation_media\gif_deploy_loading.gif'
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
print('gif_deploy_loading.gif generated successfully!')
