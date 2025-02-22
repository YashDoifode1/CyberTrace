<?php

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';


if (!isset($_GET['id'])) {
    die("Invalid request!");
}
$conn = new mysqli("localhost", "root", "", "job");
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
$id = intval($_GET['id']);
$sql = "SELECT * FROM logs WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();
$log = $result->fetch_assoc();
$ip = $log['webrtc_ip'];

if (!$log) {
    die("No record found!");
}

// Fetch Whois Data for email
// Fetch Whois Data
$whoisUrl = "https://rdap.org/ip/" . $ip;
$whoisData = file_get_contents($whoisUrl);
$whoisJson = json_decode($whoisData, true);

$emails = [];
if (!empty($whoisJson["entities"])) {
    foreach ($whoisJson["entities"] as $entity) {
        if (!empty($entity["vcardArray"][1])) {
            foreach ($entity["vcardArray"][1] as $vcard) {
                if ($vcard[0] === "email") {
                    $emails[] = htmlspecialchars($vcard[3]);
                }
            }
        }
    }
}

if (empty($emails)) {
    die("No contact emails found in Whois data.");
}

$to = implode(", ", $emails);
$subject = "Request for IPDR Details - Cybercrime Investigation";
$body = "Dear ISP,

We are conducting an official cybercrime investigation and require IPDR details for the following IP:

IP Address: {$log['ip']}
ASN: {$log['ASN']}
ISP: {$log['ISP']}
Timestamp: {$log['timestamp']}

Please provide the necessary information at your earliest convenience.

Best Regards,
Cybercrime Investigation Unit";

$mail = new PHPMailer(true);

try {
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com'; // Update SMTP server
    $mail->SMTPAuth = true;
    $mail->Username = 'yashdoifode1439@gmail.com'; // Update sender email
    $mail->Password = 'mvub juzg shso fhpa'; // Update password
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = 587;
    $mail->setFrom('your-email@example.com', 'Cyber Crime Investigation Unit');
    foreach ($emails as $email) {
        $mail->addAddress($email);
    }

    $mail->Subject = $subject;
    $mail->Body = $body;

    $mail->send();
    echo "<script>alert('Email sent successfully.'); window.location.href='admin.php';</script>";
} catch (Exception $e) {
    echo "<script>alert('Email could not be sent: {$mail->ErrorInfo}'); window.location.href='admin.php';</script>";
}
?>