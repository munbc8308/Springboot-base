package com.spring.lica.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record OAuth2ErrorResponse(
    @JsonProperty("error") String error,
    @JsonProperty("error_description") String errorDescription
) {}
