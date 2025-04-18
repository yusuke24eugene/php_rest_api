<?php

header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");


require_once('includes/config.inc.php');
require_once('includes/db.inc.php');

// Get HTTP Method
$method = $_SERVER['REQUEST_METHOD'];

// Get request parameters
$request = explode('/', trim($_SERVER['PATH_INFO'], '/'));
$input = json_decode(file_get_contents('php://input'), true);

// Route request
switch ($method) {
    case 'GET':
        handleGetRequest($pdo, $request);
        break;
    case 'POST':
        handlePostRequest($pdo, $input);
        break;
    case 'PUT':
        //
        break;
    case 'DELETE':
        //
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($pdo, $request)
{
    if (empty($request[0])) {
        // Get all users
        $stmt = $pdo->query("SELECT id, username, email, first_name, last_name, birth_date, created_at FROM users");
        $users = $stmt->fetchall(PDO::FETCH_ASSOC);
        echo json_encode($users);
    } else {
        // Get a single user
        $id = $request[0];
        $stmt = $pdo->prepare("SELECT id, username, email, first_name, last_name, birth_date, created_at FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            echo json_encode($user);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'User not found']);
        }
    }
}

function handlePostRequest($pdo, $input)
{
    $errors = [];

    // Validate username
    if (!empty($input['username'])) {
        $username = trim($input['username']);

        $minLength = 3;
        $maxLength = 15;

        if (strlen($username) < $minLength) {
            $errors['username'] = "Username must be at least $minLength characters";
        } else if (strlen($username) > $maxLength) {
            $errors['username'] = "Username must be $maxLength characters at maximum";
        }

        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            $errors['username'] = 'Username can only contain letters, numbers, underscores, and hyphens';
        }
    } else {
        $errors['username'] = 'Username is required';
    }

    // Validate email
    if (!empty($input['email'])) {
        $email = trim($input['email']);

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Email is invalid';
        }
    } else {
        $errors['email'] = 'Email is required';
    }

    // Validate first name
    if (!empty($input['firstName'])) {
        $firstName = ucfirst(trim($input['firstName']));

        $minLength = 1;
        $maxLength = 20;

        if (strlen($firstName) < $minLength) {
            $errors['firstName'] = "First name must be at least $minLength characters";
        } else if (strlen($firstName) > $maxLength) {
            $errors['firstName'] = "First name must be $maxLength characters at maximum";
        }

        if (!preg_match("/^[a-zA-ZáéíóúÁÉÍÓÚàèìòùÀÈÌÒÙ' -]+$/", $firstName)) {
            $errors['firstName'] = "First name can only contain letters, spaces, apostrophes, hyphens, and accents";
        }
    } else {
        $errors['firstName'] = 'First name is required';
    }

    // Validate Last name
    if (!empty($input['lastName'])) {
        $lastName = ucfirst(trim($input['lastName']));

        $minLength = 1;
        $maxLength = 20;

        if (strlen($lastName) < $minLength) {
            $errors['lastName'] = "Last name must be at least $minLength characters";
        } else if (strlen($lastName) > $maxLength) {
            $errors['lastName'] = "Last name must be $maxLength characters at maximum";
        }

        if (!preg_match("/^[a-zA-ZáéíóúÁÉÍÓÚàèìòùÀÈÌÒÙ' -]+$/", $lastName)) {
            $errors['lastName'] = "Last name can only contain letters, spaces, apostrophes, hyphens, and accents";
        }
    } else {
        $errors['lastName'] = 'Last name is required';
    }

    // Validate birth date
    if (!empty($input['birthDate'])) {
        $birthDate = trim($input['birthDate']);

        if (!preg_match("/^\d{4}-\d{2}-\d{2}$/", $birthDate)) {
            $errors['birthDate'] = "Invalid date format. Use YYYY-MM-DD";
        }

        list($year, $month, $day) = explode('-', $birthDate);

        if (!checkdate($month, $day, $year)) {
            $errors['birthDate'] = "Invalid birth date";
        }

        $currentDate = new DateTime();
        $birthdate = new DateTime($birthDate);

        if ($birthdate > $currentDate) {
            $errors['birthDate'] = "Birth date cannot be in the future";
        }
    } else {
        $errors['birthDate'] = 'Birth date is required';
    }

    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode($errors);
    } else {
        http_response_code(201);
        echo "POST success";
    }
}
