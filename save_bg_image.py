#!/usr/bin/env python3
"""
Script to save the IIM Indore building background image.
Creates a simple base64-encoded placeholder.
"""

import os
import base64

def save_image(output_path):
    """Save the background image to the static folder."""
    # Create the images directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Minimal JPEG placeholder (1x1 dark gray pixel, scaled up)
    # This is a real JPEG but very small; browsers will stretch it to fill the background
    jpeg_data = base64.b64decode(
        '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8VAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCwAA8A/9k='
    )
    
    with open(output_path, 'wb') as f:
        f.write(jpeg_data)
    
    print(f"✓ Background image placeholder saved to {output_path}")
    print("\nNote: This is a very small placeholder image.")
    print("To use the actual IIM Indore building image:")
    print(f"  1. Save your image as: {output_path}")
    print("  2. Recommended size: 1920x1080 or larger (JPEG/PNG)")
    print("  3. Restart the app to see the new image")

if __name__ == '__main__':
    project_root = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(project_root, 'static', 'images', 'iim-indore-bg.jpg')
    save_image(output_path)
