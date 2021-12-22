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
            User storedUser = null;

            for (User user : users) {
                if (user.getEmail().equals(email)) {
                    storedUser = user;
                }
            }

            if (storedUser == null) {
                char[] characters = password.toCharArray();
                String passwordHash = argon2.hash(20, 65536, 1, characters);
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
        User storedUser = null;

        for (User user : users) {
            if (user.getEmail().equals(email)) {
                storedUser = user;
            }
        }
        if (storedUser == null) {
            return -1;
        }

        char[] characters = password.toCharArray();
        String passwordHash = argon2.hash(40, 65536, 1, characters);
        if (!argon2.verify(storedUser.getPasswordHash(), characters)) {
            return -2;
        }
        return 1;
    }
}
