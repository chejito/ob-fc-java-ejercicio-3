import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.util.ArrayList;

/**
 * Clase permite registrarse e iniciar sesión a los usuarios.
 */
public class UserAccessSystemArgon2 {

    private final ArrayList<User> users = new ArrayList<>();
    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    /**
     * Método que permite registrar a un usuario con sus datos de usuario (e-mail y contraseña).
     *
     * @param email    String e-mail del usuario.
     * @param password String contraseña del usuario.
     * @return boolean false si el usuario está almacenado en el repositorio, true si es un nuevo usuario.
     */
    public boolean register(String email, String password) {
        if (!email.equals("") && !password.equals("")) {
            User user = findUserByEmail(email);
            if (user == null) {
                String passwordHash = getHash(password);
                users.add(new User(email, passwordHash));
                return true;
            }
        }
        return false;
    }
    /**
     * Método que permite iniciar sesión a un usuario con sus datos de usuario (e-mail y contraseña).
     *
     * @param email    String e-mail del usuario.
     * @param password String contraseña del usuario.
     * @return int -1 si el e-mail no existe, -2 si la contraseña es incorrecta y 1 si ambos son correctos.
     */
    public int login(String email, String password) {
        User user = findUserByEmail(email);
        if (user == null) {
            return -1;
        }

        String hash = getHash(password);
        if (!verifyPassword(password,user.getPasswordHash())) {
            return -2;
        }
        return 1;
    }
    /**
     * Método que devuelve un usuario almacenado en el ArrayList de usuarios.
     * Lo busca por su e-mail.
     *
     * @param email E-mail del usuario a buscar.
     * @return En caso afirmativo, el usuario. En caso negativo devuelve null.
     */
    public User findUserByEmail(String email) {
        for (User user : users) {
            if (user.getEmail().equals(email)) {
                return user;
            }
        }
        return null;
    }

    /**
     * Método que genera un código hash a partir de la contraseña aportada como String.
     *
     * @param password String contraseña del usuario.
     * @return String código hash.
     */
    private String getHash(String password) {
        char[] characters = password.toCharArray();
        return argon2.hash(20, 65536, 1, characters);
    }

    /**
     * Método que compara la contraseña aportada con el código hash almacenado del usuario.
     *
     * @param password String contraseña aportada al intentar iniciar sesión.
     * @param hash código hash almacenado en el usuario.
     * @return boolean true si coinciden, false si no coinciden.
     */
    private boolean verifyPassword(String password, String hash) {
        char[] characters = password.toCharArray();
        return argon2.verify(hash, characters);
    }
}
