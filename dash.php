<?php
// Connect to Database
$conn = new mysqli("localhost", "root", "", "job");
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

// Handle Search Query
$search = $_GET['search'] ?? '';
$sql = "SELECT * FROM logs";
if (!empty($search)) {
    $sql .= " WHERE ip LIKE '%$search%' OR real_ip LIKE '%$search%' OR ASN LIKE '%$search%' OR ISP LIKE '%$search%' OR user_agent LIKE '%$search%' OR digital_dna LIKE '%$search%'  ";
}
$sql .= " ORDER BY id DESC";

$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Panel - VPN Detection Logs</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
        }
        h2 {
            text-align: center;
        }
   
        .log-container {
            max-height: 700px;
            /* max-height:50%; */
            overflow-y: auto;
            border: 1px solid #ddd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid black;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #333;
            color: white;
        }
        .export-section {
            margin-top: 20px;
            text-align: center;
        }
        .export-section input, .export-section button {
            padding: 8px;
            margin: 5px;
        }
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
           
        }
       
        h2 {
            text-align: center;
            color: #333;
            /* padding: 20px;
            color: #333;
            color:red;
            background-color:black; */
        }
        .log-container {
            /* max-height: 300px; */
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
            background: white;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #333;
            color: white;
        }
        button {
            padding: 20px 12px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 2px;
        }
        .btn-download { background: #28a745; color: white; }
        .btn-email { background: #007bff; color: white; }
        .export-section {
            margin-top: 20px;
            padding: 10px;
            background: #f9f9f9;
            border-radius: 5px;
            text-align: center;
        }
        input, select {
            padding: 20px;
            margin: 5px;
            border-radius: 5px;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>

<div class="container">
    <h2>Admin Panel - VPN Detection Logs</h2>

    <div class="search-box">
        <form method="GET">
            <input type="text" name="search" placeholder="Search logs..." value="<?php echo htmlspecialchars($search); ?>">
            <button type="submit">Search</button>
        </form>
    </div>

    <div class="log-container">
    <table>
    <tr>
        <th>ID</th>
        <th>IP route</th>
        <th>REVERSE DNS</th>
        <th> REAL IP</th>
        <th>ISP</th>
        <th>VPN</th>
        <th>Tor</th>
        <th>Web RTC </th>
        <th>DNS </th>
       
        <th>Screen Resolution</th>
        <th>Language</th>
        <th>Timezone</th>
       
       
     
        <th>Digital DNA </th>
        <th>Whois</th>
        <th>Location Info</th>
        <th>Action</th>
        <th>Request Detail</th>
    </tr>

    <?php
if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        echo "<tr>
            <td>{$row['id']}</td>
            <td>{$row['ip']}</td>
            <td>{$row['reverse_dns']}</td>
            <td>{$row['real_ip']}</td>
            <td>{$row['ISP']}</td>
            <td>" . ($row['is_vpn'] ? '✅' : '✕') . "</td>
            <td>" . ($row['is_tor'] ? '✅' : '✕') . "</td>
            <td>{$row['webrtc_ip']}</td>
            <td>{$row['dns_leak_ip']}</td>
       
            <td>{$row['screen_resolution']}</td>
            <td>{$row['language']}</td>
            <td>{$row['timezone']}</td>
      
           
            <td>{$row['digital_dna']}</td>
                    <td>
                        <button style='background-color: #007bff; color: white; padding: 8px 12px; border: none; cursor: pointer; border-radius: 5px;' 
                            onclick=\"fetchWhois('{$row['webrtc_ip']}')\">Whois
                        </button>
                    </td>
                    <td>
                        <button style='background-color: #28a745; color: white; padding: 8px 12px; border: none; cursor: pointer; border-radius: 5px;' 
                            onclick=\"fetchLocation('{$row['webrtc_ip']}')\">Location
                        </button>
                    </td>
                    <td>
                        <a href='generate_pdf.php?id={$row['id']}' target='_blank' 
                            style='display: inline-block; background-color: #ffc107; padding: 8px 12px; text-decoration: none; color: black; border-radius: 5px; border: none; text-align: center;'>
                            Report
                        </a>
                    </td>
                    <td>
                        <a href='mail.php?id={$row['id']}' target='_blank' 
                            style='display: inline-block; background-color: #dc3545; padding: 8px 12px; text-decoration: none; color: white; border-radius: 5px; border: none; text-align: center;'>
                            Mail
                        </a>
                    </td>
                </tr>";
            }
        } else {
            echo "<tr><td colspan='15' style='text-align: center;'>No logs found</td></tr>";
        }
        ?>
        </table>
    </div>

    <div class="export-section">
        <h3>Export Logs</h3>
        <form action="export.php" method="GET">
            <label>From:</label>
            <input type="date" name="from_date" required>
            <label>To:</label>
            <input type="date" name="to_date" required>
            <button type="submit" name="format" value="pdf">Export as PDF</button>
            <button type="submit" name="format" value="csv">Export as CSV</button>
        </form>
    </div>
</div>

<script>
    function fetchWhois(ip) {
        fetch('whois.php?ip=' + ip)
        .then(response => response.json())
        .then(data => alert(JSON.stringify(data, null, 2)))
        .catch(error => alert('Error fetching Whois data'));
    }
    
    function fetchLocation(ip) {
        fetch('http://ip-api.com/json/' + ip)
        .then(response => response.json())
        .then(data => alert(`Country: ${data.country}\nCity: ${data.city}\nISP: ${data.isp}`))
        .catch(error => alert('Error fetching location data'));
    }
</script>

</body>
</html>

<?php $conn->close(); ?>
