import tkinter as tk
from dacmacs import DACMACS
from charm.toolbox.pairinggroup import PairingGroup
from assets import COLORS

class AccessControlDemo(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.geometry("1024x768")
        self.title('Tic-Tac-Sweep')
        self.config(background='#808080')

        # Global variables used across the application
        self.params = {
            # Created by CA
            'SP': None,
            'sk_CA': None,

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
        self.current_user = None

        self.dacmacs = DACMACS()

        # Page Setup
        main_frame = tk.Frame(self, width=1024, height=768, background='#808080')
        main_frame.place(x=0, y=0, width=1024, height=786) 
        self.pages = {}
        for F in (CAMenu, AAMenu, UserMenu, Logs, RegisterUserForm, RegisterAAForm, LoginAAForm, LoginUserForm, AttributeListInput):
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

        SP, MSK, (sk_CA, vk_CA) = self.controller.dacmacs.setup()
        self.controller.params['SP'] = SP
        self.controller.params['sk_CA'] = sk_CA

        self.create_elements()

    def create_elements(self):
        subtitle = ColorLabel(
            self,
            text="Certificate Authority Menu",
            color=COLORS['background'],
            font=('', 24)
        )
        subtitle.pack(pady=20)

        # Frame to group buttons
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        # Register Buttons
        ColorButton(
            btn_frame,
            "Register User",
            color=COLORS['btn_primary'],
            width=20,
            command=self.register_user
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Register AA",
            color=COLORS['btn_primary'],
            width=20,
            command=self.register_authority
        ).pack(pady=8)
        # Login Buttons
        ColorButton(
            btn_frame,
            "Login as User",
            color=COLORS['btn_success'],
            width=20,
            command=lambda: self.controller.show_page(LoginUserForm)
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Login as Authority",
            color=COLORS['btn_success'],
            width=20,
            command=lambda: self.controller.show_page(LoginAAForm)
        ).pack(pady=8)
        # View Info Buttons
        ColorButton(
            btn_frame,
            "View System Info",
            color=COLORS['btn_warning'].light(),
            width=20,
            command=self.view_system_info
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "View Logs",
            color=COLORS['btn_error'],
            width=20,
            command=lambda: self.controller.show_page(Logs)
        ).pack(pady=8)

        # Optional: system info area (can be toggled with button above)
        self.sysinfo_text = tk.Text(
            self,
            width=80,
            height=10,
            foreground=COLORS['text_secondary'],
            background=COLORS['background'].light()
        )
        self.sysinfo_text.pack(pady=20)
        self.sysinfo_text.insert("1.0", "System not initialized.\n")
        self.sysinfo_text.config(state="disabled")

    def register_user(self):
        self.controller.show_page(RegisterUserForm)

    def register_authority(self):
        self.controller.show_page(RegisterAAForm)

    def view_system_info(self):
        info = ""

        if self.controller.params['SP']:
            info += "System Parameters initialized.\n"
        else:
            info += "System Parameters not yet initialized.\n"

        if self.controller.params['authorities']:
            info += "\nRegistered Authorities:\n"
            for aid, data in self.controller.params['authorities'].items():
                info += f"  {data['info']['name']}: {data}\n"
        else:
            info += "No authorities registered.\n"

        if self.controller.params['users']:
            info += "\nRegistered Users:\n"
            for uid, data in self.controller.params['users'].items():
                info += f"  {data['info']['name']}: {data}\n"
        else:
            info += "No users registered.\n"

        self.sysinfo_text.config(state="normal")
        self.sysinfo_text.delete("1.0", tk.END)
        self.sysinfo_text.insert("1.0", info)
        self.sysinfo_text.config(state="disabled")


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
        self.create_topbar()
        self.create_menu()

    def create_topbar(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title=f"Logged in as {self.aid}",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

    def create_menu(self):
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        ColorButton(
            btn_frame,
            "Create Attributes",
            color=COLORS['btn_primary'],
            width=20,
            command=self.create_attributes
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Assign Attributes",
            color=COLORS['btn_primary'],
            width=20,
            command=self.assign_attributes
        ).pack(pady=8)

    def create_attributes(self):
        self.controller.show_page(AttributeListInput)

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

    def log_in(self):
        self.aid = self.controller.current_user
        name = self.controller.params['authorities'][self.aid]['info']['name']
        self.navbar.title_label.configure(text=f"Logged in as {name}")


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
        self.create_topbar()
        self.create_menu()

    def create_topbar(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title=f"Logged in as {self.uid}",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

    def create_menu(self):
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        ColorButton(
            btn_frame,
            "Create File",
            color=COLORS['btn_primary'],
            width=20,
            command=self.create_file
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Search File",
            color=COLORS['btn_primary'],
            width=20,
            command=self.search_file
        ).pack(pady=8)

    def create_file(self):
        pass

    def search_file(self):
        pass

    def log_in(self):
        self.uid = self.controller.current_user
        name = self.controller.params['users'][self.uid]['info']['name']
        self.navbar.title_label.configure(text=f"Logged in as {name}")


class BaseForm(tk.Frame):
    def __init__(self, parent, controller, title, back_command, submit_text, submit_command):
        super().__init__(parent, background=COLORS['background'])
        self.controller = controller
        self.fields = {}

        self.navbar = TopNavBar(
            self,
            controller,
            title=title,
            back_command=back_command,
            quit_command=controller.quit
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.form_frame = tk.Frame(self, background=COLORS['background'])
        self.form_frame.pack(pady=20)

        # Submit button
        ColorButton(
            self,
            text=submit_text,
            color=COLORS["btn_primary"],
            width=20,
            command=submit_command
        ).pack(pady=15)

    def add_field(self, label_text, field_name, row, entry_width=20, label_width=15):
        label = ColorLabel(
            self.form_frame,
            label_text,
            color=COLORS['background'],
            width=label_width,
            anchor='e'
        )
        label.grid(row=row, column=0, pady=6, sticky="e")

        entry = ColorEntry(
            self.form_frame,
            width=entry_width
        )
        entry.grid(row=row, column=1, padx=(20, 150), pady=6, sticky="w")

        self.fields[field_name] = entry

    def get_field(self, field_name):
        return self.fields[field_name].get()

    def clear_fields(self):
        for entry in self.fields.values():
            entry.delete(0, tk.END)

    def find_user(self, users, name):
        for uid, data in users.items():
            if data['info']['name'] == name:
                return uid


class RegisterAAForm(BaseForm):
    def __init__(self, parent, controller):
        super().__init__(
            parent, controller,
            title="Register AA",
            back_command=lambda: controller.show_page(CAMenu),
            submit_text="Register AA",
            submit_command=self.submit_aa
        )
        self.add_field("Full Name: ", "name", row=0)
        self.add_field("Email: ", "email", row=1)
        self.add_field("Password: ", "password", row=2)

    def submit_aa(self):
        aa_info = {
            'name': self.get_field("name"),
            'email': self.get_field("email"),
            'password': self.get_field("password"),
        }

        aid = self.controller.dacmacs.attr_auth_registration(aa_info)
        self.controller.params['authorities'][aid] = {
            'info': aa_info,
            'attributes': None,
            'public_key': None,
            'secret_key': None,
            'public_attribute_keys': None,
        }
        self.clear_fields()


class RegisterUserForm(BaseForm):
    def __init__(self, parent, controller):
        super().__init__(
            parent, controller,
            title="Register User",
            back_command=lambda: controller.show_page(CAMenu),
            submit_text="Register User",
            submit_command=self.submit_user
        )
        self.add_field("Full Name: ", "name", row=0)
        self.add_field("Email: ", "email", row=1)
        self.add_field("Birthday: ", "birthday", row=2)
        self.add_field("Password: ", "password", row=3)

    def submit_user(self):
        user_info = {
            'name': self.get_field("name"),
            'email': self.get_field("email"),
            'birthday': self.get_field("birthday"),
            'password': self.get_field("password"),
        }
        SP = self.controller.params['SP']
        sk_CA = self.controller.params['sk_CA']

        uid, (GPK, GSK), cert = self.controller.dacmacs.user_registration(SP, sk_CA, user_info)
        self.controller.params['users'][uid] = {
            'info': user_info,
            'GPK': GPK,
            'GSK': GSK,
            'certificate': cert
        }
        self.clear_fields()


class LoginAAForm(BaseForm):
    def __init__(self, parent, controller):
        super().__init__(
            parent, controller,
            title="Authority Log-in",
            back_command=lambda: controller.show_page(CAMenu),
            submit_text="Log-in",
            submit_command=self.submit_login
        )
        self.controller = controller
        self.add_field("Name: ", "name", row=0)
        self.add_field("Password: ", "password", row=1)

    def submit_login(self):
        users = self.controller.params['authorities']
        aid = self.find_user(users, self.get_field("name"))
        self.clear_fields()
        self.controller.current_user = aid
        self.controller.pages[AAMenu].log_in()
        self.controller.show_page(AAMenu)


class LoginUserForm(BaseForm):
    def __init__(self, parent, controller):
        super().__init__(
            parent, controller,
            title="User Log-in",
            back_command=lambda: controller.show_page(CAMenu),
            submit_text="Log-in",
            submit_command=self.submit_login
        )
        self.controller = controller
        self.add_field("Email: ", "email", row=0)
        self.add_field("Password: ", "password", row=1)

    def submit_login(self):
        users = self.controller.params['users']
        uid = self.find_user(users, self.get_field("name"))
        self.clear_fields()
        self.controller.current_user = uid
        self.controller.pages[UserMenu].log_in()
        self.controller.show_page(UserMenu)


class Logs(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.create_elements()
    
    def create_elements(self):
        pass


class AttributeListInput(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.entries = []

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Create New Attributes",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.entries_frame = tk.Frame(self, background=COLORS['background'])
        self.entries_frame.pack()

    def build_form(self):
        authorities = self.controller.params['authorities']
        authority = authorities[self.controller.current_user]
        attributes = authority['attributes']
        for attribute in attributes:
            self.add_entry(attribute)

        submit_btn = ColorButton(
            self,
            text="Create Attributes",
            color=COLORS['btn_success'],
            command=self.submit_attributes
        )
        submit_btn.pack(pady=10)

    def add_entry(self, attribute=None):
        if self.entries:
            prev_frame, prev_entry = self.entries[-1]
            self.add_btn.destroy()
            remove_btn = ColorButton(
                prev_frame,
                text="X",
                width=2,
                height=1,
                color=COLORS['btn_error'].light(),
                command=lambda: self.remove_entry(prev_frame)
            )
            remove_btn.pack(side="left")

        row = len(self.entries)
        frame = tk.Frame(self.entries_frame, background=COLORS['background'])
        frame.grid(row=row, column=0, pady=4)

        entry = ColorEntry(frame, width=30)
        entry.pack(side="left", padx=5)
        entry.focus_set()
        entry.insert(0, attribute)

        self.add_btn = ColorButton(
            frame,
            text="Add Attribute",
            width=10,
            height=1,
            color=COLORS['btn_primary'].light(),
            command=self.add_entry
        )
        self.add_btn.pack(side="left")

        self.entries.append((frame, entry))

    def remove_entry(self, frame):
        # Remove frame and entry
        self.entries = [pair for pair in self.entries if pair[0] != frame]
        frame.destroy()

        # Re-grid frames to account for the row ordering
        for index, (frame, _) in enumerate(self.entries):
            frame.grid_forget()
            frame.grid(row=index, column=0, pady=4)

    def get_attributes(self):
        return [e.get().strip().upper() for _, e in self.entries if e.get().strip()]

    def submit_attributes(self):
        SP = self.controller.params['SP']
        aid = self.controller.current_user
        attributes = self.get_attributes()

        sk1, pk1, attr_keys1 = self.controller.dacmacs.attr_auth_setup(SP, aid, attributes)
        authority = self.controller.params['authorities'][aid]
        authority['attributes'] = attributes
        authority['public_key'] = pk1
        authority['secret_key'] = sk1
        authority['public_attribute_keys'] = attr_keys1


class TopNavBar(tk.Frame):
    def __init__(self, parent, controller, title, back_command=None, quit_command=None, height=50):
        tk.Frame.__init__(self, parent, background=COLORS['background'].light(1.15), height=height)
        self.controller = controller

        self.color = COLORS['background'].light(1.15)

        if back_command:
            back_btn = ColorButton(
                self,
                text="← Back",
                color=self.color,
                height=3,
                width=7,
                command=back_command
            )
            back_btn.pack(side="left")

        if quit_command:
            back_btn = ColorButton(
                self,
                text="X",
                color=self.color,
                height=3,
                width=7,
                command=quit_command
            )
            back_btn.pack(side="right")

        self.title_label = tk.Label(
            self,
            text=title,
            font=('', 18),
            foreground=self.color.best_text_color(),
            background=self.color,
        )
        self.title_label.pack(side="top", pady=15)


# ======= Widgets ======= #
class ColorButton(tk.Button):
    def __init__(self, parent, text, color=COLORS['btn_primary'], font=('', 12), width=16, height=2, **kwargs):
        self.btn_color = color
        self.active_btn_color = color.dark()
        self.text_color = color.best_text_color()
        self.active_text_color = color.dark().best_text_color()

        super().__init__(
            parent,
            text=text,
            font=font,
            width=width,
            height=height,
            foreground=self.text_color,
            activeforeground=self.active_text_color,
            background=self.btn_color,
            activebackground=self.active_btn_color,
            relief='ridge',
            highlightthickness=0,
            borderwidth=0,
            **kwargs
        )


class ColorLabel(tk.Label):
    def __init__(self, parent, text, color=COLORS['background'], font=("", 16), **kwargs):
        self.label_color = color
        self.text_color = COLORS['text_primary'] if self.label_color.value < 0.6 else COLORS['black']

        super().__init__(
            parent,
            text=text,
            font=font,
            foreground=self.text_color,
            background=self.label_color,
            **kwargs
        )


class ColorEntry(tk.Entry):
    def __init__(self, parent, color=COLORS['background'], font=("", 16), width=20, **kwargs):
        self.color = color
        self.text_color = COLORS['text_primary'] if self.color.value < 0.6 else COLORS['black']

        super().__init__(
            parent,
            font=font,
            width=width,
            foreground=self.text_color,
            insertbackground=self.text_color,
            background=self.color.light(),
            relief='flat',
            highlightbackground=COLORS['gray'].dark(),
            highlightcolor=self.color.dark(),
            highlightthickness=2,
            **kwargs
        )


if __name__ == "__main__":
    root = AccessControlDemo()
    root.mainloop()
