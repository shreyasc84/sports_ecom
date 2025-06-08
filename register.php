<?php
require_once 'connection.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize form inputs
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    // Basic validation
    if (empty($username) || empty($email) || empty($password)) {
        exit('Please fill in all fields.');
    }

    // Check if username or email already exists
    $stmt = $con->prepare('SELECT user_id FROM users WHERE username = ? OR email = ?');
    $stmt->bind_param('ss', $username, $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        exit('Username or email already exists.');
    }
    $stmt->close();

    // Hash the password
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    // Insert new user into the database
    $stmt = $con->prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
    $stmt->bind_param('sss', $username, $email, $passwordHash);

    if ($stmt->execute()) {
		$stmt->close();
        header('Location: index.html?registered=1');
        exit();
    } else {
        echo 'Registration failed. Please try again.';
    }
    $stmt->close();
}
?>
