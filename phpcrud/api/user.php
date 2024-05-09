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
    if (isset($data['name']) && isset($data['username']) && isset($data['email']) && isset($data['age']) && isset($data['address']) && isset($data['password'])) {
        // Sanitize and validate input data
        $name = trim($data['name']);
        $username = trim($data['username']);
        $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
        $age = intval($data['age']);
        $address = trim($data['address']);
        $password = password_hash($data['password'], PASSWORD_DEFAULT); // Hash the password

        if ($email === false) {
            $response['error'] = 'Invalid email format';
        } elseif ($age <= 0) {
            $response['error'] = 'Invalid age';
        } else {
            // Insert user into the database
            $sql = "INSERT INTO users (name, username, email, age, address, password) VALUES (?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('sssis', $name, $username, $email, $age, $address, $password);

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
    
    // Check if a specific user ID is requested
    if (isset($_GET['id'])) {
        $id = intval($_GET['id']);

        // Retrieve user by ID
        $sql = "SELECT id, name, username, email, age, address FROM users WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('i', $id);

        if ($stmt->execute()) {
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $response = $result->fetch_assoc();
            } else {
                $response['error'] = 'User not found';
            }
        } else {
            $response['error'] = 'Failed to retrieve user';
        }
    } else {
        // Retrieve all users
        $sql = "SELECT id, name, username, email, age, address FROM users";
        $result = $conn->query($sql);

        if ($result->num_rows > 0) {
            while ($row = $result->fetch_assoc()) {
                $response[] = $row; // Add each user to the response array
            }
        } else {
            $response['error'] = 'No users found';
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    // This endpoint is for updating an existing user
    
    // Extract data from the request body
    $data = json_decode(file_get_contents('php://input'), true);

    // Check if all required fields are provided
    if (isset($data['id']) && isset($data['name']) && isset($data['username']) && isset($data['email']) && isset($data['age']) && isset($data['address']) && isset($data['password'])) {
        // Sanitize and validate input data
        $id = intval($data['id']);
        $name = trim($data['name']);
        $username = trim($data['username']);
        $email = filter_var($data['email'], FILTER_VALIDATE_EMAIL);
        $age = intval($data['age']);
        $address = trim($data['address']);
        $password = password_hash($data['password'], PASSWORD_DEFAULT); // Hash the password

        if ($email === false) {
            $response['error'] = 'Invalid email format';
        } elseif ($age <= 0) {
            $response['error'] = 'Invalid age';
        } else {
            // Update user in the database
            $sql = "UPDATE users SET name = ?, username = ?, email = ?, age = ?, address = ?, password = ? WHERE id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('sssssi', $name, $username, $email, $age, $address, $password, $id);

            if ($stmt->execute()) {
                $response['success'] = 'User updated successfully';
            } else {
                $response['error'] = 'Failed to update user';
            }
        }
    } else {
        $response['error'] = 'Missing required fields';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    // This endpoint is for deleting an existing user
    
    // Check if the user ID is provided
    if (isset($_GET['id'])) {
        $id = intval($_GET['id']);

        // Delete user from the database
        $sql = "DELETE FROM users WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('i', $id);

        if ($stmt->execute()) {
            $response['success'] = 'User deleted successfully';
        } else {
            $response['error'] = 'Failed to delete user';
        }
    } else {
        $response['error'] = 'User ID not provided';
    }
} else {
    $response['error'] = 'Invalid request method';
}

// Set response headers
header('Content-Type: application/json');

// Output response as JSON
echo json_encode($response);
