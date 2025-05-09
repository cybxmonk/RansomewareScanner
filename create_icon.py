#!/usr/bin/env python3
"""
Create a simple icon for the Ransomware Scanner application.
This script generates a PNG icon that can be converted to ICO.
"""

import os
from PIL import Image, ImageDraw, ImageFont

def create_icon(output_file="scanner.png", size=(256, 256)):
    """Create a simple icon for the application"""
    # Create a new image with white background
    img = Image.new('RGBA', size, color=(255, 255, 255, 0))
    draw = ImageDraw.Draw(img)
    
    # Calculate dimensions
    width, height = size
    center_x = width // 2
    center_y = height // 2
    radius = min(width, height) // 3
    
    # Draw a shield shape
    shield_points = [
        (center_x, center_y - radius - radius//2),  # Top point
        (center_x + radius, center_y - radius//3),  # Top right
        (center_x + radius, center_y + radius//2),  # Bottom right
        (center_x, center_y + radius + radius//3),  # Bottom point
        (center_x - radius, center_y + radius//2),  # Bottom left
        (center_x - radius, center_y - radius//3),  # Top left
    ]
    
    # Draw shield outline
    draw.polygon(shield_points, fill=(24, 99, 173, 230), outline=(0, 0, 0, 255))
    
    # Draw magnifying glass
    glass_center = (center_x - radius//3, center_y - radius//4)
    glass_radius = radius // 2
    
    # Draw glass circle
    draw.ellipse(
        (glass_center[0] - glass_radius, glass_center[1] - glass_radius,
         glass_center[0] + glass_radius, glass_center[1] + glass_radius),
        outline=(0, 0, 0, 255), width=4, fill=(255, 255, 255, 120)
    )
    
    # Draw handle
    handle_start = (
        glass_center[0] + int(glass_radius * 0.7),
        glass_center[1] + int(glass_radius * 0.7)
    )
    handle_end = (
        glass_center[0] + int(glass_radius * 1.8),
        glass_center[1] + int(glass_radius * 1.8)
    )
    draw.line([handle_start, handle_end], fill=(0, 0, 0, 255), width=6)
    
    # Draw lock symbol
    lock_center = (center_x + radius//2, center_y + radius//5)
    lock_size = radius // 2
    
    # Lock body
    draw.rectangle(
        (lock_center[0] - lock_size//2, lock_center[1] - lock_size//2,
         lock_center[0] + lock_size//2, lock_center[1] + lock_size//2),
        fill=(204, 0, 0, 230), outline=(0, 0, 0, 255), width=2
    )
    
    # Lock shackle
    shackle_width = lock_size // 3
    draw.arc(
        (lock_center[0] - shackle_width, lock_center[1] - lock_size - shackle_width//2,
         lock_center[0] + shackle_width, lock_center[1] - shackle_width//2),
        180, 0, fill=(0, 0, 0, 255), width=3
    )
    draw.line(
        [(lock_center[0] - shackle_width, lock_center[1] - shackle_width//2),
         (lock_center[0] - shackle_width, lock_center[1] - lock_size//2)],
        fill=(0, 0, 0, 255), width=3
    )
    draw.line(
        [(lock_center[0] + shackle_width, lock_center[1] - shackle_width//2),
         (lock_center[0] + shackle_width, lock_center[1] - lock_size//2)],
        fill=(0, 0, 0, 255), width=3
    )
    
    # Save the image
    img.save(output_file)
    print(f"Icon saved as {output_file}")
    
    # Convert to ICO if possible
    try:
        ico_file = os.path.splitext(output_file)[0] + ".ico"
        img.save(ico_file, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
        print(f"Icon also saved as {ico_file}")
    except Exception as e:
        print(f"Could not create ICO file: {e}")
        print("You'll need to convert the PNG to ICO manually.")

if __name__ == "__main__":
    try:
        create_icon()
    except Exception as e:
        print(f"Error creating icon: {e}")
        print("Make sure you have the Pillow library installed (pip install pillow)") 