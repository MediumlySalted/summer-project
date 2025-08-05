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
            'CA_sk': None,
            'CA_vk': None,

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
        for F in (CAMenu, RegisterUserForm, RegisterAAForm, LoginAAForm, LoginUserForm,\
                  AAMenu, CreateAttributes, SelectUser, AssignAttributes,
                  UserMenu, CreateFile, SearchFile, Logs):
            frame = F(main_frame, self)
            self.pages[F] = frame
            frame.place(x=0, y=0, width=1024, height=786)

        self.show_page(CAMenu)
        # self.setup_test()

    def show_page(self, page_class, *args, **kwargs):
        page = self.pages[page_class]

        if hasattr(page, "show"):
            page.show(*args, **kwargs)

        page.tkraise()

    def quit(self):
        self.destroy()

    def setup_test(self):
        # Test to hardcode users, authorities, and attributes
        SP = self.params['SP']
        CA_sk = self.params['CA_sk']

        # Register Users
        user1 = {
            'name': 'Alice',
            'email': 'alice@email.com',
            'birthday': '01/01/2000',
            'password': 'password'
        }
        user2 = {
            'name': 'Bob',
            'email': 'bob@email.com',
            'birthday': '12/12/1999',
            'password': 'password'
        }

        uid1, (GPK1, GSK1), cert1 = self.dacmacs.user_registration(SP, CA_sk, user1)
        self.params['users'][uid1] = {
            'info': user1,
            'GPK': GPK1,
            'GSK': GSK1,
            'certificate': cert1
        }
        uid2, (GPK2, GSK2), cert2 = self.dacmacs.user_registration(SP, CA_sk, user2)
        self.params['users'][uid2] = {
            'info': user2,
            'GPK': GPK2,
            'GSK': GSK2,
            'certificate': cert2
        }

        # Register Authorities
        auth1 = {
            'name': 'Auth1',
            'email': 'auth1@email.com',
            'password': 'password'
        }
        auth2 = {
            'name': 'Auth2',
            'email': 'auth2@email.com',
            'password': 'password'
        }

        aid1 = self.dacmacs.attr_auth_registration(auth1)
        self.params['authorities'][aid1] = {
            'info': auth1,
            'attributes': None,
            'public_key': None,
            'secret_key': None,
            'public_attribute_keys': None,
        }
        self.params['secret_keys'][aid1] = {}
        aid2 = self.dacmacs.attr_auth_registration(auth2)
        self.params['authorities'][aid2] = {
            'info': auth2,
            'attributes': None,
            'public_key': None,
            'secret_key': None,
            'public_attribute_keys': None,
        }
        self.params['secret_keys'][aid1] = {}

        # Add Attributes
        self.params['authorities'][aid1]['attributes'] = [
            f'ATTRIBUTE1@{aid1.upper()}',
            f'ATTRIBUTE2@{aid1.upper()}',
            f'ATTRIBUTE5@{aid1.upper()}'
        ]
        self.params['authorities'][aid2]['attributes'] = [
            f'ATTRIBUTE3@{aid2.upper()}',
            f'ATTRIBUTE4@{aid2.upper()}',
        ]


# =========== CAMenus =========== #
class CAMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller

        SP, MSK, (CA_sk, CA_vk) = self.controller.dacmacs.setup()
        self.controller.params['SP'] = SP
        self.controller.params['CA_sk'] = CA_sk
        self.controller.params['CA_vk'] = CA_vk

        self.create_elements()

    def create_elements(self):
        self.create_title()
        self.create_buttons()
        self.create_infobox()

    def create_title(self):
        subtitle = ColorLabel(
            self,
            text="Certificate Authority Menu",
            color=COLORS['background'],
            font=('', 24)
        )
        subtitle.pack(pady=20)

    def create_buttons(self):
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()
        # Register Buttons
        ColorButton(
            btn_frame,
            "Register User",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(RegisterUserForm)
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Register AA",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(RegisterAAForm)
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

    def create_infobox(self):
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

    def view_system_info(self):
        info = ""

        info += "Registered Authorities:\n"
        for aid, user in self.controller.params['authorities'].items():
            info += f" -{user['info']['name']}\n"
            info += f"   Email: {user['info']['email']}\n"
            info += f"   Password: {user['info']['password']}\n"
            info += f"   Attributes:\n"
            try:
                for attr in self.controller.params['authorities'][aid]['attributes']:
                    info += f"    -{attr.split("@")[0]}\n"
            except: pass

        info += "\nRegistered Users:\n"
        for uid, user in self.controller.params['users'].items():
            info += f" -{user['info']['name']}\n"
            info += f"   Email: {user['info']['email']}\n"
            info += f"   Birthday: {user['info']['birthday']}\n"
            info += f"   Password: {user['info']['password']}\n"
            info += f"   Attributes:\n"
            for aid in self.controller.params['secret_keys']:
                try:
                    for attr in self.controller.params['secret_keys'][aid][uid]['AK'].keys():
                        info += f"    -{attr.split("@")[0]}\n"
                except: pass

        self.sysinfo_text.config(state="normal")
        self.sysinfo_text.delete("1.0", tk.END)
        self.sysinfo_text.insert("1.0", info)
        self.sysinfo_text.config(state="disabled")


class BaseForm(tk.Frame):
    '''
    Parent class for setting up forms for registering and logging in.
    '''
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
        for id, data in users.items():
            if data['info']['name'] == name:
                return id


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
        self.controller.params['secret_keys'][aid] = {}

        self.clear_fields()
        self.controller.show_page(CAMenu)


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
        CA_sk = self.controller.params['CA_sk']

        uid, (GPK, GSK), cert = self.controller.dacmacs.user_registration(SP, CA_sk, user_info)
        self.controller.params['users'][uid] = {
            'info': user_info,
            'GPK': GPK,
            'GSK': GSK,
            'certificate': cert
        }
        self.clear_fields()
        self.controller.show_page(CAMenu)


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
        self.controller.show_page(AAMenu, aid)


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
        uid = self.find_user(users, self.get_field("email"))

        self.clear_fields()
        self.controller.show_page(UserMenu, uid)


# =========== AAMenus =========== #
class AAMenu(tk.Frame):
    '''
    Attribute Authority menu for handling and directing AA related operations.
    '''
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title=f"Logged in as {self.aid}",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        ColorButton(
            btn_frame,
            "Create Attributes",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(CreateAttributes, self.aid)
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Assign Attributes",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(SelectUser, self.aid)
        ).pack(pady=8)

    def show(self, aid):
        self.aid = aid
        name = self.controller.params['authorities'][self.aid]['info']['name']
        self.navbar.title_label.configure(text=f"Logged in as {name}")


class CreateAttributes(tk.Frame):
    '''
    Page for AA to create attributes.
    '''
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None
        self.entries = [] # (tk.Frame, ColorEntry)

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Create New Attributes",
            back_command=lambda: self.controller.show_page(AAMenu(self.aid)),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.entries_frame = tk.Frame(self, background=COLORS['background'])
        self.entries_frame.pack()

        ColorButton(
            self,
            text="Create Attributes",
            color=COLORS['btn_success'],
            command=self.submit_attributes
        ).pack(pady=10)

    def show(self, aid):
        self.aid = aid

        # Reset page
        self.entries = []
        for child in self.entries_frame.winfo_children():
            child.destroy()

        self.add_entry()

    def add_entry(self):
        # Updates previous add new button to a remove button
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

        # Create new entry
        row = len(self.entries)
        frame = tk.Frame(self.entries_frame, background=COLORS['background'])
        frame.grid(row=row, column=0, pady=4)

        entry = ColorEntry(frame, width=30)
        entry.pack(side="left", padx=5)
        entry.focus_set()

        # Create new add button
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
        attributes = self.get_attributes()

        sk, pk, pak = self.controller.dacmacs.attr_auth_setup(SP, self.aid, attributes)
        authority = self.controller.params['authorities'][self.aid]
        authority['attributes'] = attributes
        authority['public_key'] = pk
        authority['secret_key'] = sk
        authority['public_attribute_keys'] = pak

        self.controller.show_page(AAMenu, self.aid)


class SelectUser(tk.Frame):
    '''
    Page for AA to select a user for assigning/revoking attributes.
    '''
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None
        self.uids = []

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Select a User",
            back_command=lambda: self.controller.show_page(AAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.user_listbox = tk.Listbox(self, width=50, height=10)
        self.user_listbox.pack(pady=20)

        ColorButton(
            self,
            text="Continue",
            color=COLORS["btn_primary"],
            width=20,
            command=self.select_user
        ).pack()

    def show(self, aid):
        self.aid = aid
        self.uids = []
        self.refresh_users()

    def refresh_users(self):
        self.user_listbox.delete(0, tk.END)

        for uid, data in self.controller.params['users'].items():
            name = data['info']['name']
            self.user_listbox.insert(tk.END, name)
            self.uids.append(uid)

    def select_user(self):
        selection = self.user_listbox.curselection()
        if not selection: return

        index = selection[0]
        uid = self.uids[index]
        self.controller.show_page(AssignAttributes, self.aid, uid)


class AssignAttributes(tk.Frame):
    '''
    Page for AA to assign attributes to users.
    '''
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None
        self.uid = None
        self.attr_listbox = None
        self.user_label = None

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Assign Attributes",
            back_command=lambda: self.controller.show_page(AAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.user_label = ColorLabel(
            self,
            text="User: ",
            color=COLORS['background'],
            font=('Arial', 14)
        )
        self.user_label.pack(pady=(0, 10))

        self.attr_listbox = tk.Listbox(
            self,
            selectmode=tk.MULTIPLE,
            width=40,
            height=10
        )
        self.attr_listbox.pack(pady=10)

        ColorButton(
            self,
            text="Assign Attributes",
            color=COLORS["btn_success"],
            command=self.assign_attributes
        ).pack(pady=20)

    def show(self, aid, uid):
        self.aid = aid
        self.uid = uid
        self.update_view()

    def update_view(self):
        # Clear and update page elements
        self.attr_listbox.delete(0, tk.END)
        name = self.controller.params['users'][self.uid]['info']['name']
        self.user_label.config(text=f"Assigning Attributes to {name}: ")
        attributes = self.controller.params['authorities'][self.aid]['attributes']

        # Check for list attributes already assigned
        user_attributes = []
        try: user_attributes = list(self.controller.params['secret_keys'][self.aid][self.uid]['AK'].keys())
        except KeyError: pass

        # List attributes
        for i, attr in enumerate(attributes):
            attr_name = attr.split('@')[0]
            self.attr_listbox.insert(tk.END, attr_name)
            # Highlights attributes user already has
            if attr in user_attributes:
                self.attr_listbox.selection_set(i)

    def assign_attributes(self):
        # Get selected attributes
        selected_indices = self.attr_listbox.curselection()
        attributes = [f'{self.attr_listbox.get(i).upper()}@{self.aid.upper()}' for i in selected_indices]

        # Global parameters
        SP = self.controller.params['SP']
        CA_vk = self.controller.params['CA_vk']
        public_keys = self.controller.params['public_keys']
        public_attr_keys = self.controller.params['public_attr_keys']
        secret_keys = self.controller.params['secret_keys']
        certificate = self.controller.params['users'][self.uid]['certificate']

        # Authenticate user
        if not self.controller.dacmacs.verify_certificate(SP, certificate, CA_vk):
            self.user_label.config(text=f"Unable to verify user!")

        # Generate authority related attribute keys
        sk, pk, attr_keys = self.controller.dacmacs.attr_auth_setup(SP, self.aid, attributes)
        public_keys[self.aid] = pk
        public_attr_keys.update(attr_keys)

        # Generate user related attribute keys
        secret_keys[self.aid][self.uid] = self.controller.dacmacs.secret_key_gen(SP, sk, attr_keys, attributes, certificate)

        self.controller.show_page(AAMenu, self.aid)


class RevokeAttributes(tk.Frame):
    '''
    Page for AA to revoke attributes from users.
    '''
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.aid = None
        self.uid = None
        self.attr_listbox = None
        self.user_label = None

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Revoke Attributes",
            back_command=lambda: self.controller.show_page(AAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.user_label = ColorLabel(
            self,
            text="User: ",
            color=COLORS['background'],
            font=('Arial', 14)
        )
        self.user_label.pack(pady=(0, 10))

        self.attr_listbox = tk.Listbox(
            self,
            width=40,
            height=10
        )
        self.attr_listbox.pack(pady=10)

        ColorButton(
            self,
            text="Revoke Attributes",
            color=COLORS["btn_success"],
            command=self.assign_attributes
        ).pack(pady=20)

    def show(self, aid, uid):
        self.aid = aid
        self.uid = uid
        self.update_view()

    def update_view(self):
        # Clear and update page elements
        self.attr_listbox.delete(0, tk.END)
        name = self.controller.params['users'][self.uid]['info']['name']
        self.user_label.config(text=f"Revoke attribute from {name}: ")

        # List user's assigned attributes
        attributes = self.controller.params['secret_keys'][self.aid][self.uid]['AK'].keys()
        for attr in attributes:
            attr_name = attr.split('@')[0]
            self.attr_listbox.insert(tk.END, attr_name)

    def revoke_attribute(self, attribute):
        self.generate_update_keys()
        self.update_user_keys()
        self.update_ciphertext()

        self.controller.show_page(AAMenu, self.aid)

    def generate_update_keys(self):
        pass

    def update_user_keys(self):
        pass

    def update_ciphertext(self):
        pass


# ========== User Menus ========== #
class UserMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.uid = None

        self.create_elements()
    
    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title=f"Logged in as {self.uid}",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        ColorButton(
            btn_frame,
            "Create File",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(CreateFile)
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Search File",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(SearchFile)
        ).pack(pady=8)

    def show(self, uid):
        self.uid = uid
        name = self.controller.params['users'][self.uid]['info']['name']
        self.navbar.title_label.configure(text=f"Logged in as {name}")


class CreateFile(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Encrypt Text File",
            back_command=self.back,
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))


class SearchFile(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Decrypt Text File",
            back_command=self.back,
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))


# ========== Misc Menus ========== #
class Logs(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
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


# ======= Widgets ======= #
class TopNavBar(tk.Frame):
    def __init__(self, parent, controller, title, back_command=None, quit_command=None, height=50):
        tk.Frame.__init__(
            self,
            parent,
            background=COLORS['background'].light(1.15),
            height=height
        )
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
