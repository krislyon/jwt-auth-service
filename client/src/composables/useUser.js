import { ref, readonly } from 'vue';
import jwtDecode from 'jwt-decode'
import axios from '../composables/axiosClient'

// const USER_STATE = "user-state";

// const loadDefaultState = () => {
//     console.log('Loaded default user state from local storage');
//     const cachedUser = JSON.parse(localStorage.getItem(USER_STATE));
//     console.log(cachedUser);
//     return cachedUser ? cachedUser : {};
// }
var   authToken = "";

const currentUserState = ref({});
const loadDefaultState = async () => {
    if( authToken == "" ){
        // attempt a refresh.
        const newUserState = await axios.post('/refresh')
                                    .then( result => {
                                        if( result && result.status === 200 ){
                                            refresh( result.data.auth_token );
                                        }
                                    });
        return newUserState;
    }
}

loadDefaultState();

const login = (userdata,auth_token) => {
    const newUserState = {
        ...userdata,
        loggedIn: true,
        jwt: { ...jwtDecode(auth_token) }
    };
    currentUserState.value = newUserState;
    authToken = auth_token;

    // authToken must never be stored to localStorage or sessionStorage!!!
    //localStorage.setItem(USER_STATE, JSON.stringify(currentUserState));
}

const logout = () => {
    if( authToken !== "" ){
        console.debug('User signed out.');
        authToken = "";
    }
    currentUserState.value = {};
    //localStorage.removeItem(USER_STATE);
}

const refresh = (auth_token) => {
    const newUserState = {
        loggedIn: true,
        jwt: { ...jwtDecode(auth_token) }
    };
    currentUserState.value = newUserState;
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
