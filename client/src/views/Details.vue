<template>
    <div v-if="userState.photoURL">
        <img :src="userState.photoURL" />
    </div>
    <div>
        <table class="authPropsTable">
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Auth Token</td>
                <td>{{userState.token}}</td>
            </tr>
            <tr>
                <td>Refresh Token</td>
                <td>{{userState.refreshToken}}</td>
            </tr>
            <tr>
                <td>userState</td>
                <td>{{userState}}</td>
            </tr>

        </table>
    </div>
</template>

<script>
import { useUser } from '../composables/useUser.js'

export default {
    setup() {
        const user = useUser();
        const userState = user.state;
        return { userState };
    }
}
</script>

<style>
    .authPropsTable {
        max-width: 1024px;
        table-layout: fixed;
        width: 90%;
        overflow-wrap: break-word;
    }

</style>