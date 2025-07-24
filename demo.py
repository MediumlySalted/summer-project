import tkinter as tk
from assets import COLORS

class AccessControlDemo(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.geometry("1024x768")
        self.title('Tic-Tac-Sweep')
        self.config(background='#808080')

        # Parammeters used across the application
        self.params = {
            # Created by CA
            'SP': None,
            'secret_CA_key': None,

            # Registered through CA
            'authorities': {},
            'users': {},

            # Populated by AAs
            'secret_keys': {},
            'public_keys': {},
            'public_attr_keys': {},

            # Populated by Users
            'ciphertexts': []
        }

        # Creates parent main_frame and child menus
        # Then adds them to pages for displaying as desired 
        main_frame = tk.Frame(self, width=1024, height=768, background='#808080')
        main_frame.place(x=0, y=0, width=1024, height=786) 
        self.pages = {}
        for F in (CAMenu, AAMenu, UserMenu, Logs, ColorDemoMenu):
            frame = F(main_frame, self)
            self.pages[F] = frame
            frame.place(x=0, y=0, width=1024, height=786)

        self.show_page(CAMenu)

    def show_page(self, page_class):
        page = self.pages[page_class]
        page.tkraise()

    def quit(self):
        self.destroy()


# ======= Menus ======= #
class CAMenu(tk.Frame):
    """
    Start/Main menu of the app.

    As the certificate authority, initialize the system, register AAs, 
    and users. AA setup is handled by the AA themselves. Here you can
    also find the list of authorities and other global informaiton.

    Attributes
    ----------
    controller : Tk
        A Tk object controlling the main application
    """

    def __init__(self, parent, controller):
        """
        Menu constructor.

        Args:
            parent (tk.Frame) - Parent frame containing Menu object
            controller (tk.Tk) - Main app controller
        """
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.create_elements()

    def create_elements(self):
        ColorButton(
            self, text="Color Demo", color='btn_primary',
            command=lambda: self.controller.show_page(ColorDemoMenu)
        ).pack(pady=20)

    def register_user(self):
        pass

    def register_authority(self):
        pass


class AAMenu(tk.Frame):
    """
    Menu for handling Attribute Authority tasks.

    As an AA, create attributes and generate their version keys and
    public attribute keys, generate AA secret and public keys,
    authenticate users, and assign or revoke attributes.

    Attributes
    ----------
    controller : Tk
        A Tk object controlling the main application
    """

    def __init__(self, parent, controller):
        """
        Menu constructor.

        Args:
            parent (tk.Frame) - Parent frame containing Menu object
            controller (tk.Tk) - Main app controller
        """
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None

        self.create_elements()

    def create_elements(self):
        pass
    
    def create_attributes(self):
        pass

    def assign_attributes(self):
        self.authenticate_user()
        # assign attributes
        # ...
        # ...
        self.generate_keys()
    
    def authenticate_user(self):
        pass

    def generate_keys(self):
        pass

    def revoke_attribute(self):
        # revoke attributes
        # ...
        # ...
        self.generate_update_keys()
        self.update_user_keys()
        self.update_ciphertext()

    def generate_update_keys(self):
        pass

    def update_user_keys(self):
        pass

    def update_ciphertext(self):
        pass


class UserMenu(tk.Frame):
    """
    Menu for users to interact with the "cloud".

    As a user, encrypt and upload a "file" with a custom access control
    policy, or query a "file" and attempt to decrypt it.

    Attributes
    ----------
    controller : Tk
        A Tk object controlling the main application
    """

    def __init__(self, parent, controller):
        """
        Menu constructor.

        Args:
            parent (tk.Frame) - Parent frame containing Menu object
            controller (tk.Tk) - Main app controller
        """
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.uid = None

        self.create_elements()
    
    def create_elements(self):
        pass

    def create_file(self):
        pass

    def search_file(self):
        pass


class Logs(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.create_elements()
    
    def create_elements(self):
        pass


class ColorDemoMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'].__str__())
        self.controller = controller
        self.create_elements()

    def create_elements(self):
        title = ColorLabel(
            self,
            text='Widget Demo',
            color='background'
        )
        title.pack(pady=10)

        # ======== Labels ======== #
        color_labels = tk.Frame(self, bg=str(COLORS['background']))
        color_labels.pack(pady=10)

        row, col = 0, 0
        for color in COLORS:
            box = ColorLabel(
                color_labels,
                text=color,
                color=color,
                width=20,
                height=2
            )
            box.grid(row=row, column=col, padx=5, pady=5)

            col += 1
            if col > 3:
                row += 1
                col = 0

        # ======== Buttons ======== #
        color_buttons = tk.Frame(self, bg=str(COLORS['background']))
        color_buttons.pack(pady=20)

        ColorButton(color_buttons, text='Primary', color='btn_primary').pack(side='left', padx=10)
        ColorButton(color_buttons, text='Success', color='btn_success').pack(side='left', padx=10)
        ColorButton(color_buttons, text='Warning', color='btn_warning').pack(side='left', padx=10)
        ColorButton(color_buttons, text='Error', color='btn_error').pack(side='left', padx=10)

        # ======== Entries ======== #
        color_entries = tk.Frame(self, bg=COLORS['background'])
        color_entries.pack(pady=20)

        ColorLabel(color_entries, 'Username:', color='background').pack(anchor='w')
        ColorEntry(color_entries).pack(pady=5)
        ColorLabel(color_entries, 'Password:', color='background').pack(anchor='w')
        ColorEntry(color_entries, show='*').pack(pady=5)
        ColorButton(color_entries, 'Login', color='btn_success').pack(pady=10)


# ======= Widgets ======= #
class ColorButton(tk.Button):
    def __init__(self, parent, text, color='btn_primary', width=15, height=2, **kwargs):
        self.btn_color = COLORS[color]
        self.text_color = COLORS['text_primary'] if self.btn_color.value < 0.6 else COLORS['black']

        super().__init__(
            parent,
            text=text,
            width=width,
            height=height,
            foreground=self.text_color,
            background=self.btn_color,
            activebackground=self.btn_color.dark(),
            relief='ridge',
            highlightthickness=0,
            borderwidth=0,
            **kwargs
        )


class ColorLabel(tk.Label):
    def __init__(self, parent, text, color='background', **kwargs):
        self.label_color = COLORS[color]
        self.text_color = COLORS['text_primary'] if self.label_color.value < 0.6 else COLORS['black']

        super().__init__(
            parent,
            text=text,
            foreground=self.text_color,
            background=self.label_color,
            **kwargs
        )


class ColorEntry(tk.Entry):
    def __init__(self, parent, color='background', width=20, **kwargs):
        self.entry_color = COLORS[color]
        self.text_color = COLORS['text_primary'] if self.entry_color.value < 0.6 else COLORS['black']

        super().__init__(
            parent,
            width=width,
            foreground=self.text_color,
            insertbackground=self.text_color,
            background=self.entry_color.light(),
            relief='flat',
            highlightbackground=COLORS['gray'].dark(),
            highlightcolor=self.entry_color.dark(),
            highlightthickness=2,
            **kwargs
        )


if __name__ == "__main__":
    root = AccessControlDemo()
    root.mainloop()
