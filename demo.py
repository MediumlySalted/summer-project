import tkinter as tk
import base64, pickle
from dacmacs import DACMACS
from assets import COLORS
from tkinter import ttk
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import objectToBytes, bytesToObject
from cryptography.fernet import Fernet

class AccessControlDemo(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.width = 1024
        self.height = 768
        self.geometry(f"{self.width}x{self.height}")
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

        self.dacmacs = DACMACS()

        # Page Setup
        main_frame = tk.Frame(self, width=self.width, height=self.height, background='#808080')
        main_frame.pack()
        self.pages = {}
        for F in (CAMenu, RegisterUserForm, RegisterAAForm, LoginAAForm, LoginUserForm,
                  AAMenu, CreateAttributes, SelectUser, AssignAttributes,
                  UserMenu, CreateFile, CreateAccessPolicy, SearchFile, Logs):
            frame = F(main_frame, self)
            self.pages[F] = frame
            frame.place(x=0, y=0, width=self.width, height=self.height)

        self.show_page(CAMenu)
        self.setup_test()

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
        public_keys = self.params['public_keys']
        public_attr_keys = self.params['public_attr_keys']

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
            'files': {},
            'GPK': GPK1,
            'GSK': GSK1,
            'certificate': cert1
        }
        self.params['secret_keys'][uid1] = {}
        uid2, (GPK2, GSK2), cert2 = self.dacmacs.user_registration(SP, CA_sk, user2)
        self.params['users'][uid2] = {
            'info': user2,
            'files': {},
            'GPK': GPK2,
            'GSK': GSK2,
            'certificate': cert2
        }
        self.params['secret_keys'][uid2] = {}

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
        aid2 = self.dacmacs.attr_auth_registration(auth2)
        self.params['authorities'][aid2] = {
            'info': auth2,
            'attributes': None,
            'public_key': None,
            'secret_key': None,
            'public_attribute_keys': None,
        }

        # Add Attributes
        self.params['authorities'][aid1]['attributes'] = [
            f'ATTRIBUTE1@{aid1.upper()}',
            f'ATTRIBUTE2@{aid1.upper()}',
            f'ATTRIBUTE5@{aid1.upper()}'
            f'ATTRIBUTE3@{aid2.upper()}',
        ]
        self.params['authorities'][aid2]['attributes'] = [
            f'ATTRIBUTE3@{aid2.upper()}',
            f'ATTRIBUTE4@{aid2.upper()}',
        ]

        # Assign Attributes
        attr_aid1 = [f'ATTRIBUTE1@{aid1.upper()}', f'ATTRIBUTE2@{aid1.upper()}']
        attr_aid2 = [f'ATTRIBUTE3@{aid2.upper()}']

        sk1, pk1, attr_keys1 = self.dacmacs.attr_auth_setup(SP, aid1, attr_aid1)
        self.params['public_keys'][aid1] = pk1
        self.params['public_attr_keys'].update(attr_keys1)
        self.params['secret_keys'][uid1][aid1] = self.dacmacs.secret_key_gen(
            SP, sk1, attr_keys1, 
            attr_aid1, cert1
        )

        sk2, pk2, attr_keys2 = self.dacmacs.attr_auth_setup(SP, aid2, attr_aid2)
        self.params['public_keys'][aid2] = pk2
        self.params['public_attr_keys'].update(attr_keys2)
        self.params['secret_keys'][uid1][aid2] = self.dacmacs.secret_key_gen(
            SP, sk2, attr_keys2,
            attr_aid2, cert1
        )

        # Create File
        f = ("Test Name", "Example text line 1\nExample text line 2\n")
        access_policy = f'ATTRIBUTE1@{aid1.upper()} and ATTRIBUTE2@{aid1.upper()}'
        sym_key_elem = self.dacmacs.group.random(GT)
        sym_key_bytes = objectToBytes(sym_key_elem, self.dacmacs.group)
        fernet_key = Fernet(base64.urlsafe_b64encode(sym_key_bytes[:32]))

        file_bytes = pickle.dumps(f)
        encrypted_file = fernet_key.encrypt(file_bytes)

        ciphertext = self.dacmacs.encrypt(
            SP, public_keys, public_attr_keys,
            sym_key_elem, access_policy
        )

        file_ct = {
            "ciphertext": ciphertext,
            "encrypted_file": encrypted_file
        }

        self.params['users'][uid1]['files'][f[0]] = file_ct


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
        subtitle = TopNavBar(self, self.controller, title="Certificate Authority Menu", quit_command=self.controller.quit)
        subtitle.pack(fill='both', pady=(0, 15))

    def create_buttons(self):
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack(pady=20)
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
            for aid in self.controller.params['secret_keys'][uid]:
                auth = self.controller.params['authorities'][aid]['info']['name']
                try:
                    for attr in self.controller.params['secret_keys'][uid][aid]['AK'].keys():
                        info += f"    -{attr.split("@")[0]} ({auth})\n"
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
        self.submit_command = submit_command

        self.navbar = TopNavBar(
            self,
            controller,
            title=title,
            back_command=back_command,
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

        self.form_frame = tk.Frame(self, background=COLORS['background'])
        self.form_frame.pack(pady=20)

        ColorButton(
            self,
            text=submit_text,
            color=COLORS["btn_primary"],
            width=20,
            command=self.submit_command
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
        entry.bind("<Return>", lambda event: self.submit_command())

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

    def show(self):
        self.fields['name'].focus_set()

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

    def show(self):
        self.fields['name'].focus_set()

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
            'files': {},
            'GPK': GPK,
            'GSK': GSK,
            'certificate': cert
        }
        self.controller.params['secret_keys'][uid] = {}
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

    def show(self):
        self.fields['name'].focus_set()

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
    
    def show(self):
        self.fields['email'].focus_set()

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
        self.navbar.pack(fill='both', pady=(0, 15))

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
            back_command=lambda: self.controller.show_page(AAMenu, self.aid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

        self.entries_frame = tk.Frame(self, background=COLORS['background'])
        self.entries_frame.pack()
        self.entries_frame.bind("<Tab>", lambda event: self.add_entry())
        self.entries_frame.bind("<Return>", lambda event: self.submit_attributes())

        self.submit_btn = ColorButton(
            self,
            text="Create Attributes",
            color=COLORS['btn_success'],
            command=self.submit_attributes
        )
        self.submit_btn.pack(pady=10)
        self.submit_btn.bind("<Return>", lambda event: self.submit_attributes())

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
        entry.bind("<Tab>", lambda event: self.add_entry())
        entry.bind("<Return>", lambda event: self.submit_attributes())
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
            back_command=lambda: self.controller.show_page(AAMenu, self.aid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

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
            back_command=lambda: self.controller.show_page(AAMenu, self.aid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

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
        try: user_attributes = list(self.controller.params['secret_keys'][self.uid][self.aid]['AK'].keys())
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
        secret_keys[self.uid][self.aid] = self.controller.dacmacs.secret_key_gen(SP, sk, attr_keys, attributes, certificate)

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
            back_command=lambda: self.controller.show_page(AAMenu, self.aid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

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
        attributes = self.controller.params['secret_keys'][self.uid][self.aid]['AK'].keys()
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
        self.info = ""

        self.create_elements()

    def create_elements(self):
        self.create_navbar()
        self.create_buttons()
        self.create_infobox()

    def create_navbar(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title=f"Logged in as {self.uid}",
            back_command=lambda: self.controller.show_page(CAMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

    def create_buttons(self):
        btn_frame = tk.Frame(self, background=COLORS['background'])
        btn_frame.pack()

        ColorButton(
            btn_frame,
            "Create File",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(CreateFile, self.uid)
        ).pack(pady=8)
        ColorButton(
            btn_frame,
            "Search File",
            color=COLORS['btn_primary'],
            width=20,
            command=lambda: self.controller.show_page(SearchFile, self.uid)
        ).pack(pady=8)

    def create_infobox(self):
        self.infobox_frame = tk.Frame(self, background=COLORS['background'])
        self.infobox_frame.pack(pady=50, padx=200)

        self.infobox_label = ColorLabel(
            self.infobox_frame,
            text="User Info: ",
            color=COLORS['background'],
            font=("", 14)
        )
        self.infobox_label.pack(pady=5, anchor="w")

        self.infobox = tk.Text(
            self.infobox_frame,
            width=80,
            height=10,
            foreground=COLORS['text_secondary'],
            background=COLORS['background'].light()
        )
        self.infobox.pack(pady=10, padx=30)

    def show(self, uid):
        self.uid = uid
        self.user = self.controller.params['users'][self.uid]
        name = self.user['info']['name']
        self.navbar.title_label.configure(text=f"Logged in as {name}")

        # Add text to infobox
        self.infobox.config(state="normal")
        self.infobox.delete("1.0", tk.END)
        self.info = ""
        self.info += f"Personal Info: \n"
        self.info += f"  Email: {self.user['info']['email']}\n"
        self.info += f"  Birthday: {self.user['info']['birthday']}\n"
        self.info += f"  Password: {self.user['info']['password']}\n"
        self.info += f"\n"
        self.info += f"Your Attributes: \n"
        for aid in self.controller.params['secret_keys'][uid]:
            auth = self.controller.params['authorities'][aid]['info']['name']
            try:
                for attr in self.controller.params['secret_keys'][uid][aid]['AK'].keys():
                    self.info += f"  -{attr.split("@")[0]} ({auth})\n"
            except: pass
        self.info += f"\n"
        self.infobox.insert("1.0", self.info)
        self.infobox.config(state="disabled")


class CreateFile(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller
        self.uid = None
        self.file = None

        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Encrypt Text File",
            back_command=lambda: self.controller.show_page(UserMenu, self.uid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='both', pady=(0, 15))

        self.text_name = ColorEntry(self)
        self.text_name.pack()

        self.text_box = tk.Text(
            self,
            width=80,
            height=10,
            foreground=COLORS['text_secondary'],
            background=COLORS['background'].light()
        )
        self.text_box.pack(pady=10, padx=30)

        ColorButton(self, 'Create Access Policy', command=self.create_access_policy).pack()

    def create_access_policy(self):
        file_name = self.text_name.get()
        file_content = self.text_box.get("1.0", tk.END)
        self.file = (file_name, file_content)
        self.controller.show_page(CreateAccessPolicy, self.uid, self.file)

    def show(self, uid):
        self.text_name.focus_set()
        self.uid = uid

    def encrypt_file(self, access_policy):
        SP = self.controller.params['SP']
        public_keys = self.controller.params['public_keys']
        public_attr_keys = self.controller.params['public_attr_keys']
        sym_key_elem = self.controller.dacmacs.group.random(GT)

        # Convert GT element to Fernet key
        sym_key_bytes = objectToBytes(sym_key_elem, self.controller.dacmacs.group)
        fernet_key = Fernet(base64.urlsafe_b64encode(sym_key_bytes[:32]))

        # Encrypt file
        file_bytes = pickle.dumps(self.file)
        encrypted_file = fernet_key.encrypt(file_bytes)

        # Encrypt GT element
        ciphertext = self.controller.dacmacs.encrypt(
            SP, public_keys, public_attr_keys,
            sym_key_elem, access_policy
        )

        file_ct = {
            "ciphertext": ciphertext,
            "encrypted_file": encrypted_file
        }

        self.controller.params['users'][self.uid]['files'][self.file[0]] = file_ct


class CreateAccessPolicy(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller

        self.policy_nodes = []  # Stores policy elements (attributes & operators)
        self.authority_map = {} # Map Authority names to their uids
        self.auth_name = None
        self.uid = None
        self.message = None

        self.create_elements()

    def create_elements(self):
        self.create_navbar()
        self.create_attribute_widgets()
        self.create_control_buttons()
        self.create_policy_widget()

    def create_navbar(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Build Access Policy",
            back_command=lambda: self.controller.show_page(CreateFile, self.uid),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

    def create_attribute_widgets(self):
        attr_frame = tk.LabelFrame(
            self,
            text="Available Attributes",
            bg=COLORS['background'],
            fg=COLORS['text_primary'],
            padx=10, pady=10
        )
        attr_frame.pack(side="left", fill="y", padx=10, pady=(0, 10))

        # Authority selection dropdown
        self.authority_var = tk.StringVar()
        self.authority_dropdown = ttk.Combobox(
            attr_frame,
            textvariable=self.authority_var,
            state="readonly",
            width=25
        )
        self.authority_dropdown.pack(pady=5)
        self.authority_dropdown.bind("<<ComboboxSelected>>", self.load_attributes)

        # Listbox for attributes
        self.attr_listbox = tk.Listbox(attr_frame, selectmode="single", width=25, height=15)
        self.attr_listbox.pack(pady=5)

        self.add_btn = ColorButton(
            attr_frame,
            text="Add Selected",
            color=COLORS["btn_primary"],
            command=self.add_selected_attributes
        )
        self.add_btn.pack(pady=5)

    def create_control_buttons(self):
        controls_frame = tk.Frame(self, bg=COLORS['background'])
        controls_frame.pack(fill="x", pady=10)

        self.and_btn = ColorButton(
            controls_frame,
            text="Add AND",
            color=COLORS["btn_primary"].light(),
            command=lambda: self.add_operator("AND"),
            state='disabled'
        )
        self.and_btn.pack(side="left", padx=5)

        self.or_btn = ColorButton(
            controls_frame,
            text="Add OR",
            color=COLORS["btn_primary"].light(),
            command=lambda: self.add_operator("OR"),
            state='disabled'
        )
        self.or_btn.pack(side="left", padx=5)

        ColorButton(
            controls_frame,
            text="Clear",
            color=COLORS["btn_error"],
            command=self.clear_policy,
            state='normal'
        ).pack(side="left", padx=5)
        ColorButton(
            controls_frame,
            text="Save Policy",
            color=COLORS["btn_primary"],
            command=self.save_policy,
            state='normal'
        ).pack(side="left", padx=5)

    def create_policy_widget(self):
        # ====== Policy Interface ====== #
        policy_frame = tk.LabelFrame(
            self,
            text="Policy Preview",
            bg=COLORS['background'],
            fg=COLORS['text_primary'],
            padx=10, pady=10
        )
        policy_frame.pack(side="right", fill="both", expand=True, padx=10, pady=(0, 10))

        # Scrollable canvas
        self.canvas = tk.Canvas(policy_frame, bg=COLORS['background'], highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        self.preview_text = self.canvas.create_text(
            10, 10,
            text="No policy defined yet.",
            anchor="nw",
            fill=COLORS['text_primary'],
            font=("Arial", 12)
        )

    def show(self, uid, message):
        self.uid = uid
        self.message = message
        self.update_authority_dropdown()

    def update_authority_dropdown(self):
        self.authority_map.clear()
        auth_names = []

        for aid, auth in self.controller.params["authorities"].items():
            name = auth["info"]["name"]
            auth_names.append(name)
            self.authority_map[name] = aid
        self.authority_dropdown['values'] = auth_names

        if auth_names:
            self.authority_dropdown.current(0)
            self.load_attributes()

    def load_attributes(self, event=None):
        self.attr_listbox.delete(0, tk.END)
        self.auth_name = self.authority_var.get()
        aid = self.authority_map[self.auth_name]
        attributes = self.controller.params["authorities"][aid]["attributes"]
        for attr in attributes:
            self.attr_listbox.insert(tk.END, attr.split("@")[0])

    def add_selected_attributes(self):
        selected_index = self.attr_listbox.curselection()
        attr_name = self.attr_listbox.get(selected_index)
        self.policy_nodes.append(f'{attr_name}@{self.auth_name}')

        self.and_btn.configure(state='normal')
        self.or_btn.configure(state='normal')
        self.add_btn.configure(state='disabled')
        self.update_policy_preview()

    def add_operator(self, op):
        if not self.policy_nodes:
            return
        self.policy_nodes.append(op)

        self.and_btn.configure(state='disabled')
        self.or_btn.configure(state='disabled')
        self.add_btn.configure(state='normal')
        self.update_policy_preview()

    def update_policy_preview(self):
        preview_str = " ".join(self.policy_nodes)
        self.canvas.itemconfig(self.preview_text, text=preview_str)

    def clear_policy(self):
        self.policy_nodes.clear()
        self.update_policy_preview()

    def save_policy(self):
        for i, policy_node in enumerate(self.policy_nodes):
            if i % 2 == 0:
                attr, auth_name = policy_node.split("@")
                self.policy_nodes[i] = f'{attr}@{self.authority_map[auth_name].upper()}'
            
            if i % 2 == 1:
                self.policy_nodes[i] = policy_node.lower()

        policy_str = " ".join(self.policy_nodes)
        self.controller.pages[CreateFile].encrypt_file(policy_str)
        self.controller.show_page(UserMenu, self.uid)


class SearchFile(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, background=COLORS['background'])
        self.controller = controller

        self.uid = None
        self.file = None
        self.users = None
        self.selected_uid = None
        self.selected_user = tk.StringVar(value="")
        self.selected_file = tk.StringVar()
        self.create_elements()

    def create_elements(self):
        self.navbar = TopNavBar(
            self,
            self.controller,
            title="Search & Decrypt File",
            back_command=lambda: self.controller.show_page(UserMenu),
            quit_command=lambda: self.controller.quit()
        )
        self.navbar.pack(fill='x', pady=(0, 20))

        self.form_frame = tk.Frame(self, background=COLORS['background'])
        self.form_frame.pack(pady=10, fill="x")

        self.create_user_selection()
        self.create_file_selection()
        self.create_file_display()

    def create_user_selection(self):
        ColorLabel(self.form_frame, "Select User:").grid(row=0, column=0, sticky="e", padx=10, pady=5)

        self.user_menu = tk.OptionMenu(
            self.form_frame,
            self.selected_user,
            *'Select User',
        )
        self.user_menu.config(width=20)
        self.user_menu.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.selected_user.trace_add("write", self.populate_files)

    def create_file_selection(self):
        ColorLabel(self.form_frame, "Files: ").grid(row=1, column=0, sticky="ne", padx=10, pady=5)

        self.file_listbox = tk.Listbox(self.form_frame, width=40, height=8)
        self.file_listbox.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Decrypt button
        ColorButton(
            self,
            text="Decrypt File",
            color=COLORS['btn_primary'],
            width=20,
            command=self.decrypt_selected_file
        ).pack(pady=15)

    def create_file_display(self):
        self.result_label = ColorLabel(self, "Decrypted File: ")
        self.result_label.pack(pady=(20, 5))

        self.result_text = tk.Text(
            self, width=80, height=10, wrap="word",
            bg=COLORS['background'].light(), fg=COLORS['text_primary']
        )
        self.result_text.pack(pady=5)

    def show(self, uid):
        self.uid = uid

        # Populate user list
        users = self.controller.params.get('users', {})
        if users:
            menu = self.user_menu["menu"]
            menu.delete(0, "end")
            for uid, user in users.items():
                name = user['info']['name']
                menu.add_command(
                    label=name,
                    command=lambda x=uid, y=name: self.select_user(x, y)
                )

    def select_user(self, uid, name):
        self.selected_uid = uid
        self.selected_user.set(name)

    def populate_files(self, *args):
        # Populate the listbox with files created by the selected user
        self.file_listbox.delete(0, tk.END)
        files = self.controller.params['users'][self.selected_uid].get('files', {})
        for fname in files.keys():
            self.file_listbox.insert(tk.END, fname)

    def decrypt_selected_file(self):
        selection = self.file_listbox.curselection()
        if not self.selected_uid or not selection:
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, "No user or file selected.")
            return
        
        file_name = self.file_listbox.get(selection[0])
        try:
            file_ct = self.controller.params['users'][self.selected_uid]['files'][file_name]
            GPK = self.controller.params['users'][self.uid]['GPK']
            GSK = self.controller.params['users'][self.uid]['GSK']
            secret_keys = self.controller.params['secret_keys'][self.uid]

            # Generate decryption token
            TK = self.controller.dacmacs.token_gen(file_ct['ciphertext'], GPK, secret_keys)
            sym_key_elem = self.controller.dacmacs.decrypt(file_ct['ciphertext'], TK, GSK)

            # Convert GT element to Fernet key
            sym_key_bytes = objectToBytes(sym_key_elem, self.controller.dacmacs.group)
            fernet_key = Fernet(base64.urlsafe_b64encode(sym_key_bytes[:32]))

            # Decrypt file
            file_bytes = fernet_key.decrypt(file_ct["encrypted_file"])
            decrypted_file = pickle.loads(file_bytes)
            fname, fcontent = decrypted_file
            
            # Display file
            self.result_label.configure(text=f'Decrypted File: {fname}')
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, fcontent)

        except Exception as e:
            self.result_label.configure(text=f'Decrypted File: ')
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f'ERROR: {e}')


# =========== Widgets ============ #
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

        back_btn = ColorButton(
            self,
            text="← Back",
            color=self.color,
            height=3,
            width=7,
            command=back_command
        )
        back_btn.pack(side="left")

        quit_btn = ColorButton(
            self,
            text="X",
            color=self.color,
            height=3,
            width=7,
            command=quit_command
        )
        quit_btn.pack(side="right")

        if not back_command: back_btn.configure(text='', state='disabled')
        if not quit_command: quit_btn.configure(text='', state='disabled')

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
