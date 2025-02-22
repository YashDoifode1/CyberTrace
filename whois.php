<?php
if (isset($_GET['ip'])) {
    $ip = filter_var($_GET['ip'], FILTER_VALIDATE_IP);
    if ($ip) {
        $whoisUrl = "https://rdap.org/ip/" . $ip;
        $whoisData = file_get_contents($whoisUrl);
        
        if ($whoisData) {
            $whoisJson = json_decode($whoisData, true);
            
            // Extract required details
            $output = [
                "country" => $whoisJson["country"] ?? "N/A",
                "email" => [],
                "tel" => [],
                "adr" => [],
                "events" => $whoisJson["events"] ?? "N/A",
                "handle" => $whoisJson["handle"] ?? "N/A"
            ];

            // Extract emails, telephone numbers, and addresses if they exist
            if (!empty($whoisJson["entities"])) {
                foreach ($whoisJson["entities"] as $entity) {
                    if (!empty($entity["vcardArray"][1])) {
                        foreach ($entity["vcardArray"][1] as $vcard) {
                            if ($vcard[0] === "email") {
                                $output["email"][] = $vcard[3];
                            } elseif ($vcard[0] === "tel") {
                                $output["tel"][] = $vcard[3];
                            } elseif ($vcard[0] === "adr") {
                                $output["adr"][] = implode(", ", array_filter($vcard[3]));
                            }
                        }
                    }
                }
            }

            header('Content-Type: application/json');
            echo json_encode($output, JSON_PRETTY_PRINT);
        } else {
            echo json_encode(["error" => "Whois data not found."]);
        }
    } else {
        echo json_encode(["error" => "Invalid IP address."]);
    }
} else {
    echo json_encode(["error" => "No IP address provided."]);
}
?>
