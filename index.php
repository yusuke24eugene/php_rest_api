<?php

header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

require_once('includes/config.inc.php');
require_once('includes/db.inc.php');
require_once('vendor/autoload.php');

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// Get HTTP Method
$method = $_SERVER['REQUEST_METHOD'];

// Get request parameters
$request = explode('/', trim($_SERVER['PATH_INFO'], '/'));
$input = json_decode(file_get_contents('php://input'), true);

// Route request
switch ($method) {
    case 'GET':
        if (validateToken($pdo)) {
            handleGetRequest($pdo, $request);
        }
        break;
    case 'POST':
        if ($request[0] === 'login') {
            login($pdo, $input);
        } else if ($request[0] === 'register') {
            handlePostRequest($pdo, $input);
        } else if ($request[0] === 'logout') {
            logout($pdo);
        }
        break;
    case 'PUT':
        handlePutRequest($pdo, $request, $input);
        break;
    case 'DELETE':
        handleDeleteRequest($pdo, $request);
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
        $username = htmlspecialchars(strip_tags(trim($input['username'])));

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

        $stmt = $pdo->prepare("SELECT username FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            $errors['username'] = 'Username is already taken';
        }
    } else {
        $errors['username'] = 'Username is required';
    }

    // Validate email
    if (!empty($input['email'])) {
        $email = htmlspecialchars(strip_tags(trim($input['email'])));

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'Email is invalid';
        }

        $stmt = $pdo->prepare("SELECT email FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            $errors['email'] = 'Email is already taken';
        }
    } else {
        $errors['email'] = 'Email is required';
    }

    // Validate and hashed password
    if (!empty($input['password'])) {
        $password = htmlspecialchars(strip_tags(trim($input['password'])));
        $options = ['cost' => 12];
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT, $options);
    } else {
        $errors['password'] = 'Password is required';
    }

    // Validate password confirmation
    if (!empty($input['confirmPassword'])) {
        $confirmPassword = htmlspecialchars(strip_tags(trim($input['confirmPassword'])));
        if ($password !== $confirmPassword) {
            $errors['confirmPassword'] = 'Password confirmation does not match';
        }
    } else {
        $errors['confirmPassword'] = 'Password confirmation is required';
    }

    // Validate first name
    if (!empty($input['firstName'])) {
        $firstName = htmlspecialchars(strip_tags(ucfirst(trim($input['firstName']))));

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
        $lastName = htmlspecialchars(strip_tags(ucfirst(trim($input['lastName']))));

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
        $birthDate = htmlspecialchars(strip_tags(trim($input['birthDate'])));

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
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password, first_name, last_name, birth_date) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->execute([$username, $email, $hashedPassword, $firstName, $lastName, $birthDate]);
        $id = $pdo->lastInsertId();

        $stmt = $pdo->prepare("SELECT id, username, email, first_name, last_name, birth_date, created_at FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            http_response_code(201);
            echo json_encode($user);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'User not found']);
        }
    }
}

function handlePutRequest($pdo, $request, $input)
{
    $errors = [];

    if (!empty($request[0])) {
        $id = $request[0];
        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            // Validate username
            if (!empty($input['username'])) {
                $username = htmlspecialchars(strip_tags(trim($input['username'])));

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

                $stmt = $pdo->prepare("SELECT username FROM users WHERE id = ?");
                $stmt->execute([$id]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($result && $result['username'] !== $username) {
                    $stmt = $pdo->prepare("SELECT username FROM users WHERE username = ?");
                    $stmt->execute([$username]);
                    $result = $stmt->fetch(PDO::FETCH_ASSOC);

                    if ($result) {
                        $errors['username'] = 'Username is already taken';
                    }
                }
            } else {
                $errors['username'] = 'Username is required';
            }

            // Validate email
            if (!empty($input['email'])) {
                $email = htmlspecialchars(strip_tags(trim($input['email'])));

                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    $errors['email'] = 'Email is invalid';
                }

                $stmt = $pdo->prepare("SELECT email FROM users WHERE id = ?");
                $stmt->execute([$id]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($result && $result['email'] !== $email) {
                    $stmt = $pdo->prepare("SELECT email FROM users WHERE email = ?");
                    $stmt->execute([$email]);
                    $result = $stmt->fetch(PDO::FETCH_ASSOC);

                    if ($result) {
                        $errors['email'] = 'Email is already taken';
                    }
                }
            } else {
                $errors['email'] = 'Email is required';
            }

            // Validate and hashed password
            if (!empty($input['password'])) {
                $password = htmlspecialchars(strip_tags(trim($input['password'])));
                $options = ['cost' => 12];
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT, $options);
            } else {
                $errors['password'] = 'Password is required';
            }

            // Validate password confirmation
            if (!empty($input['confirmPassword'])) {
                $confirmPassword = htmlspecialchars(strip_tags($input['confirmPassword']));
                if ($password !== $confirmPassword) {
                    $errors['confirmPassword'] = 'Password confirmation does not match';
                }
            } else {
                $errors['confirmPassword'] = 'Password confirmation is required';
            }

            // Validate first name
            if (!empty($input['firstName'])) {
                $firstName = htmlspecialchars(strip_tags(ucfirst(trim($input['firstName']))));

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
                $lastName = htmlspecialchars(strip_tags(ucfirst(trim($input['lastName']))));

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
                $birthDate = htmlspecialchars(strip_tags(trim($input['birthDate'])));

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
                $stmt = $pdo->prepare("UPDATE users SET username = ?, email = ?, password = ?, first_name = ?, last_name = ?, birth_date = ? WHERE id = ?");
                $stmt->execute([$username, $email, $hashedPassword, $firstName, $lastName, $birthDate, $id]);

                $stmt = $pdo->prepare("SELECT id, username, email, first_name, last_name, birth_date, created_at FROM users WHERE id = ?");
                $stmt->execute([$id]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($user) {
                    http_response_code(201);
                    echo json_encode($user);
                } else {
                    http_response_code(404);
                    echo json_encode(['error' => 'User not found']);
                }
            }
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Not Found']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'There is no parameter']);
    }
}

function handleDeleteRequest($pdo, $request)
{
    if (!empty($request[0])) {
        $id = $request[0];

        $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$id]);

            $stmt = $pdo->prepare("SELECT id FROM users WHERE id = ?");
            $stmt->execute([$id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                http_response_code(202);
                echo json_encode(['message' => 'Item deleted successfully']);
            }
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Not Found']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'There is no parameter']);
    }
}

function login($pdo, $input)
{
    $errors = [];

    $username = htmlspecialchars(strip_tags(trim($input['username'])));
    $password = htmlspecialchars(strip_tags(trim($input['password'])));

    if (!empty($username)) {
        $stmt = $pdo->prepare("SELECT id, username, email, password FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            if (!empty($password)) {
                if (password_verify($password, $result['password'])) {
                    $secret_key = "secret_key";
                    $issuer_claim = "issuer";
                    $audience_claim = "audience";
                    $issuedat_claim = time();
                    $expire_claim = $issuedat_claim + 3600; // 1 hour
    
                    $token = array(
                        "iss" => $issuer_claim,
                        "aud" => $audience_claim,
                        "iat" => $issuedat_claim,
                        "exp" => $expire_claim,
                        "data" => array(
                            "id" => $result['id'],
                            "username" => $result['username'],
                            "email" => $result['email']
                        )
                    );
    
                    $jwt = JWT::encode($token, $secret_key, 'HS256');
    
                    http_response_code(200);
                    echo json_encode([
                        "message" => "Login successful",
                        "token" => $jwt,
                        "expiresAt" => $expire_claim
                    ]);
                } else {
                    $errors['password'] = 'Password is incorrect';
                }    
            } else {
                $errors['password'] = 'Password is required';
            }
        } else {
            $errors['username'] = 'Username does not exists';
        }
    } else {
        $errors['username'] = 'Username is required';
    }

    if ($errors) {
        http_response_code(400);
        echo json_encode($errors);
    }
}

function validateToken($pdo)
{
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? '';

    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $jwt = $matches[1];
        try {
            $secret_key = "secret_key";
            $decoded = JWT::decode($jwt, new Key($secret_key, 'HS256'));

            if ($decoded) {
                if ($decoded->exp <= time()) {
                    http_response_code(401);
                    echo json_encode(["message" => "Acess denied"]);
                    return false;
                }

                $stmt = $pdo->prepare("SELECT token FROM blacklist_token WHERE token = ?");
                $stmt->execute([$jwt]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($result) {
                    http_response_code(401);
                    echo json_encode(["message" => "Access Denied"]);
                    return false;
                }

                $stmt = $pdo->prepare("SELECT username, email FROM users WHERE id = ?");
                $stmt->execute([$decoded->data->id]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($result['username'] === $decoded->data->username && $result['email'] === $decoded->data->email) {
                    return true;                  
                } else {
                    http_response_code(401);
                    echo json_encode(["message" => "Access denied"]);
                    return false;
                }
            }
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode([
                "message" => "Access denied",
                "error" => $e->getMessage()
            ]);
            return false;
        }
    } else {
        http_response_code(401);
        echo json_encode(["message" => "Access denied"]);
        return false;
    }
}

function logout($pdo)
{
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? '';

    if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        $jwt = $matches[1];
        try {
            $secret_key = "secret_key";
            $decoded = JWT::decode($jwt, new Key($secret_key, 'HS256'));

            if ($decoded) {
                $stmt = $pdo->prepare("INSERT INTO blacklist_token (token, user_id, username, email, expiration) VALUES (?, ?, ?, ?, ?)");
                $stmt->execute([$jwt, $decoded->data->id, $decoded->data->username, $decoded->data->email, $decoded->exp]);

                $stmt = $pdo->prepare("SELECT token FROM blacklist_token WHERE token = ? AND user_id = ?");
                $stmt->execute([$jwt, $decoded->data->id]);
                $result = $stmt->fetch(PDO::FETCH_ASSOC);

                if ($result) {
                    http_response_code(200);
                    echo json_encode(["message" => "Logged out"]);
                } else {
                    http_response_code(401);
                    echo json_encode(["message" => "Invalid token"]);
                }
            }
        } catch (Exception $e) {
            http_response_code(401);
            echo json_encode([
                "message" => "Tokken error",
                "error" => $e->getMessage()
            ]);
        }
    }
}
