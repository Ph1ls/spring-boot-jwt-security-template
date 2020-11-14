package de.phil.jwt.mongodb.models;

public enum ERole {
  ROLE_USER("user"),
  ROLE_MODERATOR("mod"),
  ROLE_ADMIN("admin");

  private final String rolename;

  ERole(final String rolename) {
    this.rolename = rolename;
  }

  public static ERole of(String rolename) {
    if (ROLE_USER.rolename.equals(rolename)) {return ROLE_USER;}
    if (ROLE_ADMIN.rolename.equals(rolename)) {return ROLE_ADMIN;}
    if (ROLE_MODERATOR.rolename.equals(rolename)) {return ROLE_MODERATOR;}
    return null;
  }
}
