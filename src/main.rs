use std::fs::{self, File};
use std::io::{self, Write };
use magic_crypt::{new_magic_crypt, MagicCryptTrait};

use whoami;

fn main() {
  // Determine the username of the user using the program.
  // This will be used to determine where to write this user's passwords.
  let username: String = whoami::username().trim().to_string();

  // Before anything else, the user needs to provide their 'master' password.
  // This password will only be stored in memory for the duration of the program.
  // This is the password that will be used to encrypt passwords that are stored on disk.
  // This will also be used to decrypted stored passwords for the user.
  println!("Enter your master password:");
  let mut master_password = String::new();
  io::stdin().read_line(&mut master_password).expect("Failed to read the master password");
  println!("");

  master_password = master_password.trim().to_string();

  // Once the username and master password have been determined, the program needs to display
  // the options that the user can take.
  println!("Please select an action:");
  let user_choice = determine_user_choice();


  match user_choice.as_ref() {
    "1" => add_password(&username, &master_password),
    "2" => view_password_entries(&username, &master_password),
    _ => unreachable!(),
  }
}

// This function determines what action the user wants to take.
// They can either add a new password, or view their existing passwords.
// This became a separate function so that if the user enters a bad choice (IE: not 1 or 2),
// we can recursively prompt the user to make a decision.
fn determine_user_choice() -> String {
  println!("  1.) Add password");
  println!("  2.) View saved passwords");

  let mut user_choice = String::new();
  io::stdin().read_line(&mut user_choice).expect("Failed to read user choice");

  // Match the user's choice to make sure they made a valid choice.
  // Don't do anything if it's valid, but recurse if it's not.
  match user_choice.trim() {
    "1" => {},
    "2" => {},
    _ => {
      // The user entered an invalid choice. Re-call this function to prompt them to make a valid selection.
      println!("WTF you doing? Enter a legit option ya jabroni!\n");
      determine_user_choice();
    },
  }
  println!("");
  // Finally, return the user choice.
  user_choice.trim().to_string()
}

fn determine_user_password_choice(username: &str) -> String {
  let password_dir = format!("./passwords/{}", username);
  let paths = fs::read_dir(password_dir).unwrap();

  for path in paths {
    let file_name = path.unwrap().path().file_stem().unwrap().to_string_lossy().to_string();
    println!("  '{}'", file_name);
  }
  println!("");

  let mut user_password_choice = String::new();
  io::stdin().read_line(&mut user_password_choice).expect("Failed to read user choice");

  println!("");
  let file_stems: Vec<_> = fs::read_dir(format!("./passwords/{}", username))
    .unwrap()
    .filter_map(|entry| entry.ok()) // ignore any errors
    .filter(|entry| entry.path().is_file()) // only keep files
    .map(|entry| entry.path().file_stem().unwrap().to_string_lossy().to_string())
    .collect();

    if !file_stems.contains(&user_password_choice) {
      println!("File name {} not found, please try again. These are your saved password entries:", user_password_choice.trim().to_string());
      determine_user_password_choice(&username);
    }
    // Finally, return the user choice.
    user_password_choice.trim().to_string()
}

// This function adds a new password entry to disk. It accepts the username
// and the master password that should be used to encrypt the password.
fn add_password(username: &str, master_password: &str) -> () {
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
  password_entry.write_to_file(&username, &master_password).expect("Failed to write to file");
}

// This function should print out all of the saved passwords 'entries' for the user.
// It should then force the user to select which entry they want to view the password for.
// Once the user makes a decision, the password will be displayed to stdout.
// This function relies on the master password that the user entered to decrypt the saved passwords.
// It is implied that the master password provided is the same password that the user used to encrypt
// the passwords on disk in the first place.
fn view_password_entries(username: &str, master_password: &str) -> () {
  println!("Please enter the name of the application or website you want to view:");
  println!("");
  println!("These are your saved password entries:");

  let file_stem = determine_user_password_choice(username);

  let file_path = format!("./passwords/{}/{}.txt", username, file_stem);

  let encrypted_file_contents = fs::read_to_string(file_path).expect("Failed to read file");

  let mc = new_magic_crypt!(master_password, 256);
  let decrypted_password = mc.decrypt_base64_to_string(&encrypted_file_contents.trim().to_string());

  match decrypted_password {
    Ok(res) => { println!("decrypted_password: {}", res); },
    Err(err) => println!("Error: {}", err),
  }
}

#[derive(Debug)]
struct PasswordEntry {
  name: String,
  password: String,
}

impl PasswordEntry {
  fn write_to_file(&self, username: &str, master_password: &str) -> io::Result<()> {
    let mc = new_magic_crypt!(master_password, 256);

    let base64_password = mc.encrypt_str_to_base64(&self.password);

    // create a directory for the user if it doesn't exist
    let user_password_dir = "passwords/".to_string() + username;

    fs::create_dir_all(user_password_dir)?;

    // Create a file with the name of the service or website
    let mut file = File::create(format!("passwords/{}/{}.txt", username, self.name))?;

    // Write the encrypted password to the file
    writeln!(file, "{}", base64_password)?;

    println!("A new password for {} has been successfully added!", self.name);
    Ok(())
  }
}
