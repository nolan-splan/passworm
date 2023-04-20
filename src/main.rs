use std::fs::{self, File};
use std::io::{self, Write };
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use clap::Parser;
use whoami;

#[derive(Parser, Debug)]
#[command(author="", version="0.0.1", about="Simple CLI password manager", long_about = None)]
#[clap(name = "passworm")]
struct Args {
    #[clap(short, long)]
    add: bool,
    #[clap(short, long)]
    view: bool,
}

struct User {
  username: String,
  password: String,
}

impl User {
  fn new() -> Self {
    // Determine the username of the user using the program.
    // This will be used to determine where to write this user's passwords.
    let username: String = whoami::username().trim().to_string();

    // Before anything else, the user needs to provide their 'master' password.
    // This password will only be stored in memory for the duration of the program.
    // This is the password that will be used to encrypt passwords that are stored on disk.
    // This will also be used to decrypted stored passwords for the user.
    println!("Enter your master password:");
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read the master password");
    password = password.trim().to_string();
    println!();

    User { username: username, password: password }
  }

  fn add_password(&mut self) -> () {
    // The name they enter here will be used as the filename for the new password entry.
    println!("Enter the application or website name:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).expect("Failed to read name");
    println!("");

    println!("Enter your password for '{}':", name.trim());
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read password");
    println!("");

    // Create a new password entry to store the provided information.
    let password_entry = PasswordEntry {
      name: name.trim().to_string(),
      password: password.trim().to_string(),
    };

    // Write the new password entry to disk.
    password_entry.write_to_file(&self.username, &self.password).expect("Failed to write to file");
  }

  fn view_passwords(&mut self) -> () {
    // Set a variable for the directory that the user's password files are stored in
    let password_dir = format!("./passwords/{}", &self.username).clone();

    // Get the paths of each of the user's password files in the password directory
    let paths = fs::read_dir(password_dir).unwrap();


    let mc = new_magic_crypt!(&self.password, 256);

    println!("Your saved passwords are:");

    // Iterate over each of the password file paths
    for path in paths {
      let file_name = path
        .as_ref()
        .map(|dir_entry| {
          dir_entry
            .path()
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .to_string()
        })
        .unwrap();

      let file_path = path
        .as_ref()
        .map(|dir_entry| {
          dir_entry
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string()
        })
        .unwrap();

      let password_path = format!("{}/{}", format!("./passwords/{}", &self.username), file_path);

      let encrypted_file_contents = fs::read_to_string(password_path).expect("Failed to read file").trim().to_string();

      let decrypted_password = mc.decrypt_base64_to_string(&encrypted_file_contents);

      let decrypted_password_str = match decrypted_password {
        Ok(res) => res,
        Err(_err) => "Invalid Master Password!".to_string(),
      };

      // Print out the file stem, followed by the decrypted password
      println!("  {}: {}", file_name, decrypted_password_str);
    }
    println!("");
  }
}

fn main() {
  // Parse the command line arguments
  let args = Args::parse();

  // Determine the proper workflow for the given args
  if args.add {
    let mut user = User::new();
    user.add_password();
  } else if args.view {
    let mut user = User::new();
    user.view_passwords()
  } else {
    println!("both args were false");
  }
}

struct PasswordEntry {
  name: String,
  password: String,
}

impl PasswordEntry {
  fn write_to_file(&self, username: &str, master_password: &str) -> io::Result<()> {
    // Generate the encrypted password that will be stored in the file.
    let encrypted_password = generate_encrypted_password(&self.password, master_password);

    // create a directory to store the user's passwords (if one doesn't exist already)
    let user_password_dir = "passwords/".to_string() + username;

    fs::create_dir_all(user_password_dir.clone())?;

    // Create a file with the name of the service or website
    let mut file = File::create(format!("{}/{}.txt", user_password_dir, self.name))?;

    // Write the encrypted password to the file
    writeln!(file, "{}", encrypted_password)?;

    println!("A new password for '{}' has been successfully added!", self.name);
    Ok(())
  }
}

// This function generates a random salt and uses it to encrypt the given password using the master_password
// as the encryption key. It then returns the encrypted password in a Base64-encoded string format.
fn generate_encrypted_password(password: &str, master_password: &str) -> String {
  let mc = new_magic_crypt!(master_password, 256);

  mc.encrypt_str_to_base64(&password)
}