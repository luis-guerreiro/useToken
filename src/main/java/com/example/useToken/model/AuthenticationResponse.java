package com.example.useToken.model;

public class AuthenticationResponse {

    //essa classe vai voltar com o token, necessariamente somente para fazer o teste
    private final String jwt;

    public AuthenticationResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
