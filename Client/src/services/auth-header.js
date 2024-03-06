import axios from "axios";

const API_URL = "http://localhost:8080/api/auth/";

export default async function authHeader() {
  let accessToken = JSON.parse(localStorage.getItem("accessToken"));
  const refreshToken = JSON.parse(localStorage.getItem("refreshToken"));

  if (accessToken) {
    const jwtPayload = JSON.parse(window.atob(accessToken.split('.')[1]));
    if (jwtPayload.exp-10 < Math.floor(Date.now() / 1000)) {
      console.log('get access token');
      await axios
        .post(API_URL + "getAccessToken", {
          refreshToken
        })
        .then((response) => {
          console.log(response);
          if (response.data) {
            localStorage.setItem("accessToken", JSON.stringify(response.data.accessToken));
            accessToken = response.data.accessToken;
            console.log('acessToken has');
          }
          else{
            localStorage.removeItem("user");
            localStorage.removeItem("accessToken");
            localStorage.removeItem("refreshToken");
          }
        });
    }
    // For Spring Boot back-end
    // return { Authorization: "Bearer " + user.accessToken };

    // for Node.js Express back-end
    console.log(accessToken);
    return { "x-access-token": accessToken };
  } else {
    console.log('accessToken Null');
    return {};
  }
}
