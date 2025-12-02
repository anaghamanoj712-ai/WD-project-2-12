import base64
import sys

# The image you provided - I'll encode it properly
# For now, using the existing placeholder and you can replace it
image_path = "static/images/iim-indore-bg.jpg"

try:
    with open(image_path, 'rb') as f:
        image_data = f.read()
    
    base64_str = base64.b64encode(image_data).decode('utf-8')
    print(f"Base64 encoded image (length: {len(base64_str)} chars):")
    print(f"image_base64 = '{base64_str}'")
    
    # Save to a file for easy copying
    with open('bg_base64.txt', 'w') as f:
        f.write(f"image_base64 = '{base64_str}'")
    print("\n✓ Saved to bg_base64.txt")
except Exception as e:
    print(f"Error: {e}")
