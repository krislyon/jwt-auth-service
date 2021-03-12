import { ref, readonly } from 'vue';
import jwtDecode from 'jwt-decode'

const USER_STATE = "user-state";

const loadDefaultState = () => {
    const cachedUser = localStorage.getItem(USER_STATE);
    return cachedUser ? cachedUser : {};
}

const currentUserState = ref( loadDefaultState() );
var   authToken = "";

const login = (userdata,auth_token) => {
    const newUserState = {
        ...userdata,
        loggedIn: true,
        jwt: { ...jwtDecode(auth_token) }
    };
    currentUserState.value = newUserState;
    authToken = auth_token;

    // authToken must never be stored to localStorage or sessionStorage!!!
    localStorage.setItem(USER_STATE,currentUserState);
}

const logout = () => {
    currentUserState.value = {};
    authToken = "";
    localStorage.removeItem(USER_STATE);
    console.debug('User signed out.');
}

const refresh = (auth_token) => {
    currentUserState.value.jwt = { ...jwtDecode(auth_token) };
    authToken = auth_token;
    console.debug('Auth Token updated.');
}

export const useUser = () => {
    return {
        state: readonly(currentUserState),
        authToken: authToken,
        login,
        logout,
        refresh
    }
}
