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
        h = self.hue * 360
        s = self.saturation * 100
        v = min(self.value * amount, 1.0) * 100
        return Color(h, s, v)

    def dark(self, amount=0.8):
        # Reduce value
        return self.adjust_value(amount)

    def light(self, amount=1.2):
        # Increase value
        return self.adjust_value(amount)

    def best_text_color(self):
        # Choose between black or white text for best contrast
        r, g, b = colorsys.hsv_to_rgb(*self.hsv)

        # Convert RGB to linearized values
        def linearize(c):
            if c <= 0.03928:
                return c / 12.92
            return ((c + 0.055) / 1.055) ** 2.4

        r_lin = linearize(r)
        g_lin = linearize(g)
        b_lin = linearize(b)

        # Compute relative luminance
        luminance = 0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin

        # Compute contrast ratios
        contrast_white = (1.05) / (luminance + 0.05)
        contrast_black = (luminance + 0.05) / 0.05

        # Higher contrast is better
        return '#FFFFFF' if contrast_white >= contrast_black else '#000000'

