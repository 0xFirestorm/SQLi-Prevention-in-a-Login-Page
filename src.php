<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Portal</title>
    <style>
        body {
            background-image: url(bg3.jpg);
            background-size: cover; /* Cover the entire viewport */
            background-position: center; /* Center the background image */
        }
        .php{
            color: white;
            text-align: center;
            font-size: medium;
        }
        .labels{
            color: white
        }
        .image{
            width: 50%;
            margin-left: auto;
            margin-right: auto;
     
            text-align: center;
            margin-top: 5%;
        }
        .form{
            padding: 10px;
        
            text-align: center;
            height: 100%;
            width: 50%;
            margin-left: auto;
            margin-right: auto;
        }
        label{
            margin: 8px;
        }
        input[name="username"],input[name="password"]{
            padding: 16px;
            margin: 8px;
            border: 1px solid black;
            border-radius: 5px;
            letter-spacing: 1px;
            width: 274px;

        }
        input[name="login"]{
            padding: 16px;
            margin: 8px;
            width: 274px;
            background-color: seagreen;
            border-radius: 5px;
            color: white;
            font-weight: 600;
            border: none;
            cursor: pointer;
        }
        input[name="login"]:hover {
            background-color: green; /* Change to your desired color */
        }
        .name{
            margin-top: 20px;
            font-family: "Helvetica", sans-serif;
            font-weight: 900;
            font-size: 50px;
            color: greenyellow;
            text-align: center;
        }
    </style>
</head>
<body>
        <div class="name">NOT FOODPANDA</div>
        <div class="image">
            
            <img src="logo.png">
        </div>

        <div class="form">
        <form action method="post" autocomplete="off">
            <label for="username" class="labels">Username</label><br>
            <input type="text" name="username" placeholder="Enter your username"><br>
            <label for="password" class="labels">Password</label><br>
            <input type="password" name="password" placeholder="********" ><br>
            <input type="submit" name="login" value="login">
            </form>
        </div>
    
</body>
</html>

<?php
$hostname="localhost";
$username="root";
$password="";
$dbname="test";
$conn=mysqli_connect($hostname, $username, $password, $dbname);
if(!$conn){
    die("Unable to CONNECT");
}
if($_POST){
    $uname = $_POST["username"];
    $password = $_POST["password"];

    // Input Validation
    if (!preg_match("/^[a-zA-Z0-9]*$/", $uname)) {
        echo '<div class="php"> Invalid Characters Detected! </div>';
        exit;
    }

    // Limiting to 3 attempts per IP address)
    $ip = $_SERVER['REMOTE_ADDR'];
    $maxAttempts = 3;
    $timeWindow = 3600; // 1 hour
    $currentTime = time();
    $earliestTime = $currentTime - $timeWindow;
    $stmt = $conn->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND timestamp > ?");
    $stmt->bind_param("si", $ip, $earliestTime);
    $stmt->execute();
    $stmt->bind_result($attempts);
    $stmt->fetch();
    $stmt->close();
    if ($attempts >= $maxAttempts) {
        echo '<div class="php"> Max Login Attempts Exceeded! </div>';;
        exit;
    }

    // SQL Injection Prevention
    $sql = "SELECT username,password FROM users WHERE username = ? AND password = ?";
    $stmt = mysqli_prepare($conn, $sql);
    if($stmt){
        mysqli_stmt_bind_param($stmt,"ss", $uname, $password);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $resuser, $respass);
        mysqli_stmt_fetch($stmt);
        if(!empty($resuser) AND !empty($respass)){
            echo '<div class="php"> Login Successful </div>';
        }
        else{
            echo '<div class="php"> Invalid Username/Password </div>';          
            // Record failed login attempt
            $stmt2 = $conn->prepare("INSERT INTO login_attempts (ip, timestamp) VALUES (?, ?)");
            $stmt2->bind_param("si", $ip, $currentTime);
            $stmt2->execute();
            $stmt2->close();
        }
        mysqli_stmt_close($stmt);
    }
}
?>
