<template>
  <nav>
    <div id="nav">
        <router-link to="/">Home</router-link>
        <span v-if="userState.loggedIn">
             | <router-link to="/details">User Details</router-link>
             | <a href="" @click.prevent="handleSignOut">Logout</a>
        </span>
        <span v-else> | <router-link to="/login">Login</router-link></span>
    </div>
  </nav>
</template>

<script>
import { useUser } from '../composables/useUser.js'
import axios from '../composables/axiosClient'
import { useRouter } from 'vue-router'

export default {
    setup(){
        const user = useUser();
        const userState = user.state;
        const router = useRouter();

        const handleSignOut = async () => {
            const user = useUser();
            if( user.state.value.loggedIn ){
                let res = await axios.post( '/logout', { userId: user.state.value.jwt.userId } );
                if( res.status != 200 ){
                    console.log('Failed to retrieve salt');
                    return;
                }
                user.logout();
            }
            router.push({ name: 'Login'});
        };

        return {
            handleSignOut,
            userState,
        }
    }

}
</script>

<style>

</style>