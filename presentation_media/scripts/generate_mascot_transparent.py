from PIL import Image

img = Image.open(r'c:\Progects\HoneyForge\presentation_media\mascot_bear.png').convert('RGBA')
# Keep original as mascot_bear.png, make a cutout version mascot_bear_transparent.png
datas = img.getdata()

newData = []
for item in datas:
    # If pixel is very close to the deep dark background corners
    r, g, b, a = item
    brightness = (r + g + b) / 3
    if brightness < 22 and r < 30 and g < 25 and b < 22:
        newData.append((r, g, b, 0))
    elif brightness < 35 and r < 40 and g < 32 and b < 28:
        alpha = int(255 * (brightness - 22) / 13)
        newData.append((r, g, b, alpha))
    else:
        newData.append(item)

img_trans = Image.new('RGBA', img.size)
img_trans.putdata(newData)
img_trans.save(r'c:\Progects\HoneyForge\presentation_media\mascot_bear_transparent.png', 'PNG')
print('mascot_bear_transparent.png saved successfully')
