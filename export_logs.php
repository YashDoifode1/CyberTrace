<?php
// Connect to Database
$conn = new mysqli("localhost", "root", "", "job");
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

// Get export format and date range
$format = $_GET['format'] ?? 'csv';
$start_date = $_GET['start_date'] ?? '';
$end_date = $_GET['end_date'] ?? '';

$sql = "SELECT * FROM logs";
if (!empty($start_date) && !empty($end_date)) {
    $sql .= " WHERE created_at BETWEEN '$start_date' AND '$end_date'";
}
$result = $conn->query($sql);

if ($format == 'csv') {
    header("Content-Type: text/csv");
    header("Content-Disposition: attachment; filename=logs.csv");
    
    $output = fopen("php://output", "w");
    fputcsv($output, ["ID", "IP Route", "Reverse DNS", "Real IP", "ISP", "VPN", "Tor", "WebRTC", "DNS", "User Agent", "Screen Resolution", "Language", "Timezone", "Cookies Enabled", "Referrer", "Plugins"]);
    
    while ($row = $result->fetch_assoc()) {
        fputcsv($output, [
            $row['id'], $row['ip'], $row['reverse_dns'], $row['real_ip'], $row['ISP'],
            $row['is_vpn'] ? '✅' : '✕', $row['is_tor'] ? '✅' : '✕', $row['webrtc_ip'], $row['dns_leak_ip'],
            $row['user_agent'], $row['screen_resolution'], $row['language'], $row['timezone'],
            $row['cookies_enabled'], $row['referrer'], $row['plugins']
        ]);
    }
    fclose($output);
    exit;
}

if ($format == 'pdf') {
    require_once('tcpdf/tcpdf.php');
    $pdf = new TCPDF();
    $pdf->AddPage();
    $pdf->SetFont('helvetica', '', 10);
    $html = '<h2>VPN Detection Logs</h2><table border="1" cellpadding="5">
        <tr>
            <th>ID</th><th>IP Route</th><th>Reverse DNS</th><th>Real IP</th><th>ISP</th>
            <th>VPN</th><th>Tor</th><th>WebRTC</th><th>DNS</th><th>User Agent</th>
            <th>Screen Resolution</th><th>Language</th><th>Timezone</th><th>Cookies Enabled</th>
            <th>Referrer</th><th>Plugins</th>
        </tr>';
    
    while ($row = $result->fetch_assoc()) {
        $html .= "<tr>
            <td>{$row['id']}</td>
            <td>{$row['ip']}</td>
            <td>{$row['reverse_dns']}</td>
            <td>{$row['real_ip']}</td>
            <td>{$row['ISP']}</td>
            <td>" . ($row['is_vpn'] ? '✅' : '✕') . "</td>
            <td>" . ($row['is_tor'] ? '✅' : '✕') . "</td>
            <td>{$row['webrtc_ip']}</td>
            <td>{$row['dns_leak_ip']}</td>
            <td>{$row['user_agent']}</td>
            <td>{$row['screen_resolution']}</td>
            <td>{$row['language']}</td>
            <td>{$row['timezone']}</td>
            <td>{$row['cookies_enabled']}</td>
            <td>{$row['referrer']}</td>
            <td>{$row['plugins']}</td>
        </tr>";
    }
    $html .= '</table>';
    $pdf->writeHTML($html);
    $pdf->Output('logs.pdf', 'D');
    exit;
}

$conn->close();
?>
