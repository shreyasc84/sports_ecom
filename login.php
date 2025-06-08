<?php
require_once 'connection.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve and sanitize form inputs
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    // Basic validation
    if (empty($username) || empty($password)) {
        exit('Please fill in all fields.');
    }

    // Fetch user data from the database
    $stmt = $con->prepare('SELECT user_id, password_hash FROM users WHERE username = ?');
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows === 1) {
        // Bind result variables
        $stmt->bind_result($user_id, $passwordHash);
        $stmt->fetch();

        // Verify the password
        if (password_verify($password, $passwordHash)) {
            // Password is correct; start a new session
            $_SESSION['user_id'] = $user_id;
            $_SESSION['username'] = $username;
            header('Location: index.html?registered=1');
            exit();
        } else {
            echo 'Incorrect password.';
        }
    } else {
        echo 'Username not found.';
    }
    $stmt->close();
}
?>

