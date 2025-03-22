# laravel-project
Platform for affiliates to run their business

CREATE DATABASE affiliate_platform;

USE affiliate_platform;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'affiliate') DEFAULT 'affiliate',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE affiliates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    referral_code VARCHAR(50) NOT NULL,
    earnings DECIMAL(10, 2) DEFAULT 0.00,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE commissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    affiliate_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (affiliate_id) REFERENCES affiliates(id)
);<?php
$host = 'localhost';
$db = 'affiliate_platform';
$user = 'root';
$pass = '';

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
2.2. User Registration (register.php)
<?php
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $email = $_POST['email'];
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);

    $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $email, $password);

    if ($stmt->execute()) {
        $user_id = $stmt->insert_id;
        $referral_code = uniqid('REF_');
        $stmt = $conn->prepare("INSERT INTO affiliates (user_id, referral_code) VALUES (?, ?)");
        $stmt->bind_param("is", $user_id, $referral_code);
        $stmt->execute();

        echo "Registration successful! Your referral code: $referral_code";
    } else {
        echo "Error: " . $stmt->error;
    }
}
?>

<form method="POST" action="">
    <input type="text" name="username" placeholder="Username" required>
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Register</button>
</form>
2.3. User Login (login.php)
<?php
session_start();
include 'db.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header("Location: dashboard.php");
        } else {
            echo "Invalid password!";
        }
    } else {
        echo "User not found!";
    }
}
?>

<form method="POST" action="">
    <input type="email" name="email" placeholder="Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
</form>
2.4. Affiliate Dashboard (dashboard.php)
<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];

// Fetch affiliate details
$stmt = $conn->prepare("SELECT referral_code, earnings FROM affiliates WHERE user_id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$affiliate = $result->fetch_assoc();

// Fetch commission history
$stmt = $conn->prepare("SELECT amount, created_at FROM commissions WHERE affiliate_id = ?");
$stmt->bind_param("i", $affiliate['id']);
$stmt->execute();
$commissions = $stmt->get_result();
?>

<h1>Welcome, <?php echo $_SESSION['username']; ?>!</h1>
<p>Your Referral Code: <?php echo $affiliate['referral_code']; ?></p>
<p>Total Earnings: $<?php echo $affiliate['earnings']; ?></p>

<h2>Commission History</h2>
<table border="1">
    <tr>
        <th>Amount</th>
        <th>Date</th>
    </tr>
    <?php while ($row = $commissions->fetch_assoc()) { ?>
        <tr>
            <td>$<?php echo $row['amount']; ?></td>
            <td><?php echo $row['created_at']; ?></td>
        </tr>
    <?php } ?>
</table>
1.1. Add a Table for Tracking Links
CREATE TABLE tracking_links (
    id INT AUTO_INCREMENT PRIMARY KEY,
    affiliate_id INT NOT NULL,
    product_id INT NOT NULL,
    tracking_link VARCHAR(255) NOT NULL,
    clicks INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (affiliate_id) REFERENCES affiliates(id)
);
1.2. Generate Tracking Links (generate_link.php)
<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $product_id = $_POST['product_id'];
    $affiliate_id = $_SESSION['user_id'];

    // Generate a unique tracking link
    $tracking_link = "https:/toolsvault.online/track.php?ref=" . uniqid();

    $stmt = $conn->prepare("INSERT INTO tracking_links (affiliate_id, product_id, tracking_link) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $affiliate_id, $product_id, $tracking_link);

    if ($stmt->execute()) {
        echo "Tracking link generated: <a href='$tracking_link'>$tracking_link</a>";
    } else {
        echo "Error: " . $stmt->error;
    }
}
?>

<form method="POST" action="">
    <input type="number" name="product_id" placeholder="Product ID" required>
    <button type="submit">Generate Link</button>
</form>
1.3. Track Clicks (track.php)
<?php
include 'db.php';

if (isset($_GET['ref'])) {
    $tracking_link = "https://yourdomain.com/track.php?ref=" . $_GET['ref'];

    // Update click count
    $stmt = $conn->prepare("UPDATE tracking_links SET clicks = clicks + 1 WHERE tracking_link = ?");
    $stmt->bind_param("s", $tracking_link);
    $stmt->execute();

    // Redirect to the product page
    header("Location: product_page.php");
    exit();
}
?>
2. Payment Processing
2.1. Add PayPal Integration
Use the PayPal SDK to process payments. Install the SDK via Composer:

composer require paypal/rest-api-sdk-php
2.2. Process Payment (process_payment.php)
<?php
require 'vendor/autoload.php';

use PayPal\Api\Amount;
use PayPal\Api\Payer;
use PayPal\Api\Payment;
use PayPal\Api\RedirectUrls;
use PayPal\Api\Transaction;

$apiContext = new \PayPal\Rest\ApiContext(
    new \PayPal\Auth\OAuthTokenCredential(
        'YOUR_CLIENT_ID',     // Client ID
        'YOUR_CLIENT_SECRET'  // Client Secret
    )
);

$payer = new Payer();
$payer->setPaymentMethod('paypal');

$amount = new Amount();
$amount->setTotal('10.00'); // Total amount
$amount->setCurrency('USD');

$transaction = new Transaction();
$transaction->setAmount($amount);

$redirectUrls = new RedirectUrls();
$redirectUrls->setReturnUrl('https://yourdomain.com/success.php')
    ->setCancelUrl('https://yourdomain.com/cancel.php');

$payment = new Payment();
$payment->setIntent('sale')
    ->setPayer($payer)
    ->setTransactions([$transaction])
    ->setRedirectUrls($redirectUrls);

try {
    $payment->create($apiContext);
    header("Location: " . $payment->getApprovalLink());
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}
?>
3. Analytics and Reporting
3.1. Add Analytics Dashboard (analytics.php)
<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

$affiliate_id = $_SESSION['user_id'];

// Fetch total clicks
$stmt = $conn->prepare("SELECT SUM(clicks) AS total_clicks FROM tracking_links WHERE affiliate_id = ?");
$stmt->bind_param("i", $affiliate_id);
$stmt->execute();
$result = $stmt->get_result();
$total_clicks = $result->fetch_assoc()['total_clicks'];

// Fetch total earnings
$stmt = $conn->prepare("SELECT SUM(amount) AS total_earnings FROM commissions WHERE affiliate_id = ?");
$stmt->bind_param("i", $affiliate_id);
$stmt->execute();
$result = $stmt->get_result();
$total_earnings = $result->fetch_assoc()['total_earnings'];
?>

<h1>Analytics Dashboard</h1>
<p>Total Clicks: <?php echo $total_clicks; ?></p>
<p>Total Earnings: $<?php echo $total_earnings; ?></p>
4. Admin Panel
4.1. Add Admin Dashboard (admin.php)
<?php
session_start();
include 'db.php';

if (!isset($_SESSION['user_id']) || $_SESSION['role'] != 'admin') {
    header("Location: login.php");
    exit();
}

// Fetch all affiliates
$stmt = $conn->prepare("SELECT users.username, affiliates.referral_code, affiliates.earnings FROM affiliates JOIN users ON affiliates.user_id = users.id");
$stmt->execute();
$affiliates = $stmt->get_result();
?>

<h1>Admin Dashboard</h1>
<table border="1">
    <tr>
        <th>Username</th>
        <th>Referral Code</th>
        <th>Earnings</th>
    </tr>
    <?php while ($row = $affiliates->fetch_assoc()) { ?>
        <tr>
            <td><?php echo $row['username']; ?></td>
            <td><?php echo $row['referral_code']; ?></td>
            <td>$<?php echo $row['earnings']; ?></td>
        </tr>
    <?php } ?>
</table>
5. Security Measures
5.1. Input Validation
Always sanitize and validate user inputs:

$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
5.2. CSRF Protection
Add CSRF tokens to forms:

session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<form method="POST" action="">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
    <!-- Other form fields -->
</form>
Validate CSRF tokens on form submission:

if ($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF token validation failed!");
}
