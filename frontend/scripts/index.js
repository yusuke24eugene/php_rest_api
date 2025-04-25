/*const hamburger = document.getElementById("hamburger");
const navLinks = document.querySelector(".nav-links");

// Toggle the 'active' class on the navbar links when the hamburger icon is clicked
hamburger.addEventListener("click", () => {
  navLinks.classList.toggle("active");
});*/

// Get the current year dynamically and set it in the footer
const yearElement = document.getElementById("year");
const currentYear = new Date().getFullYear();
yearElement.textContent = currentYear;

const apiUrl = "http://localhost/php_rest_api/index.php/";
const bearerToken = localStorage.getItem('access_token');

// Function to fetch data from the PHP backend using AJAX
function fetchData() {
  fetch(apiUrl, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${bearerToken}`,
      "Content-Type": "application/json"
    },
  })
    .then((response) => response.json()) // Convert response to JSON
    .then((data) => {
      // Get the table body element
      const tableBody = document.querySelector("#data-table tbody");

      // Loop through the data and create table rows
      data.forEach((item) => {
        // Create a new row
        const row = document.createElement("tr");

        // Create cells for each piece of data
        const idCell = document.createElement("td");
        idCell.textContent = item.id;
        row.appendChild(idCell);

        const userNameCell = document.createElement("td");
        userNameCell.textContent = item.username;
        row.appendChild(userNameCell);

        const emailCell = document.createElement("td");
        emailCell.textContent = item.email;
        row.appendChild(emailCell);

        const firstNameCell = document.createElement("td");
        firstNameCell.textContent = item.first_name;
        row.appendChild(firstNameCell);

        const lastNameCell = document.createElement("td");
        lastNameCell.textContent = item.last_name;
        row.appendChild(lastNameCell);

        const birthDateCell = document.createElement("td");
        birthDateCell.textContent = item.birth_date;
        row.appendChild(birthDateCell);

        const createdAtCell = document.createElement("td");
        createdAtCell.textContent = item.created_at;
        row.appendChild(createdAtCell);

        // Append the row to the table body
        tableBody.appendChild(row);

        row.addEventListener('click', () => {
          window.location.href = "singlePage.html?id=" + item.id;
        });
      });
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