import colorsys

class Color:
    """
    Class for creating hsv colors from something interpretable,
    darkening/brightening them, and returning them as hex values
    """

    def __init__(self, h, s, v):
        self.hue = h / 360
        self.saturation = s / 100
        self.value = v / 100
        self.hsv = (self.hue, self.saturation, self.value)

    def __str__(self):
        # Return color as a hexcode.
        return self.hexify(colorsys.hsv_to_rgb(*self.hsv))

    def hexify(self, rgb):
        return '#{:02x}{:02x}{:02x}'.format(
            int(rgb[0]*255),
            int(rgb[1]*255),
            int(rgb[2]*255)
        )

    def adjust_value(self, amount):
        # Adjust value by specified amount
        rgb = colorsys.hsv_to_rgb(self.hue, self.saturation,
                                  min(self.value * amount, 1.0))
        return self.hexify(rgb)

    def dark(self, amount=0.8):
        # Reduce value
        return self.adjust_value(amount)

    def light(self, amount=1.2):
        # Increase value
        return self.adjust_value(amount)

