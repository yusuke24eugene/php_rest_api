// Get the current year dynamically and set it in the footer
const yearElement = document.getElementById("year");
const currentYear = new Date().getFullYear();
yearElement.textContent = currentYear;

const apiUrl = "http://localhost/php_rest_api/index.php/";
const bearerToken = localStorage.getItem('access_token');

// Function to fetch data from the PHP backend using AJAX
function fetchData() {
  const searchParams = new URLSearchParams(window.location.search);
  const userId = searchParams.get('id');

  fetch(apiUrl + userId, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${bearerToken}`,
      "Content-Type": "application/json"
    },
  })
    .then((response) => response.json())
    .then((data) => {
      const id = document.querySelector("#id");
      id.textContent = data.id;

      const username = document.querySelector("#username");
      username.textContent = data.username;
      sessionStorage.setItem('username', data.username);

      const email = document.querySelector("#email");
      email.textContent = data.email;
      sessionStorage.setItem('email', data.email);

      const firstName = document.querySelector("#firstName");
      firstName.textContent = data.first_name;
      sessionStorage.setItem('firstName', data.first_name);

      const lastName = document.querySelector("#lastName");
      lastName.textContent = data.last_name;
      sessionStorage.setItem('lastName', data.last_name);

      const birthDate = document.querySelector("#birthDate");
      birthDate.textContent = data.birth_date;
      sessionStorage.setItem('birthDate', data.birth_date);
    })
    .catch((error) => {
      console.error("Error fetching data:", error);
      window.location.href = 'login.html';
    });
}

// Fetch the data when the page loads
window.onload = fetchData;

async function logout(event) {
    event.preventDefault();  // Prevent default form submission

    try {
      response = await fetch(apiUrl + 'logout', {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${bearerToken}`,
          "Content-Type": "application/json"
        },
      })

      let jsonResponse = await response.json();
      
      if (response.ok) {
        localStorage.removeItem('access_token');
        console.log(jsonResponse.message);
        window.location.href = 'login.html';
      } else {
        console.log(jsonResponse.message);
        window.location.href = 'login.html';
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      window.location.href = 'login.html';
    }
}

async function destroy() {
  if(confirm('Are you sure you want to delete?')) {
    const searchParams = new URLSearchParams(window.location.search);
    const userId = searchParams.get('id');
  
    fetch(apiUrl + userId, {
      method: "DELETE",
      headers: {
        "Authorization": `Bearer ${bearerToken}`,
        "Content-Type": "application/json"
      },
    })
      .then((response) => {
        console.log('Message: ' + response.json());
  
        if (response.ok) {
          alert("Successfully deleted!");
          window.location.href = 'login.html';
        } else {
          alert("There is an error!");
          window.location.href = 'login.html';
        }
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
        window.location.href = 'login.html';
      });  
  }
}