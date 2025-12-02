import requests
import os

def ensure_bg_image():
    """Download IIM Indore image on app startup"""
    img_path = os.path.join(os.path.dirname(__file__), 'static', 'images', 'iim-indore-bg.jpg')
    
    # If doesn't exist or is too small (placeholder), download real one
    if not os.path.exists(img_path) or os.path.getsize(img_path) < 5000:
        try:
            print("Downloading IIM Indore background image...")
            os.makedirs(os.path.dirname(img_path), exist_ok=True)
            url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/4/49/Indian_Institute_of_Management_Indore.jpg/1280px-Indian_Institute_of_Management_Indore.jpg'
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                with open(img_path, 'wb') as f:
                    f.write(response.content)
                print(f"✓ Background image downloaded ({len(response.content)} bytes)")
        except Exception as e:
            print(f"Could not download image: {e}")

if __name__ == "__main__":
    ensure_bg_image()
