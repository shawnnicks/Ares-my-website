<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    
    $username = isset($_POST['username']) ? htmlspecialchars($_POST['username']) : '';
    $password = isset($_POST['password']) ? htmlspecialchars($_POST['password']) : '';

    
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

 
    $conn = new mysqli('localhost', 'root', '', 'user_db');  // Change database credentials if needed

   
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    
    $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $hashed_password);  // "ss" stands for two strings

    
    if ($stmt->execute()) {
        
        header("Location: main-menu.html");
        exit();
    } else {
        echo "Error: " . $stmt->error;
    }

   
    $stmt->close();
    $conn->close();
} else {
  
    header("Location: login.html");
    exit();
}
?>
