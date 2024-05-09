<?php

// Include the database connection file
require_once 'db_connection.php';

// Initialize response array
$response = [];

// Check the request method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // This endpoint is for creating a new user
    
    // Extract data from the request body
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if all required fields are provided
    if (isset($data['username']) && isset($data['email']) && isset($data['password'])) {
        // Sanitize and validate input data
        $username = trim($data['username']);
        $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
        $password = password_hash($data['password'], PASSWORD_DEFAULT); // Hash the password

        if ($email === false) {
            $response['error'] = 'Invalid email format';
        } else {
            // Insert user into the database
            $sql = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('sss', $username, $email, $password);

            if ($stmt->execute()) {
                $response['success'] = 'User created successfully';
            } else {
                $response['error'] = 'Failed to create user';
            }
        }
    } else {
        $response['error'] = 'Missing required fields';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // This endpoint is for retrieving user data

    // Example: Retrieve all users
    $sql = "SELECT * FROM users";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        while ($row = $result->fetch_assoc()) {
            $response[] = $row; // Add each user to the response array
        }
    } else {
        $response['error'] = 'No users found';
    }
} else {
    $response['error'] = 'Invalid request method';
}

// Set response headers
header('Content-Type: application/json');

// Output response as JSON
echo json_encode($response);
