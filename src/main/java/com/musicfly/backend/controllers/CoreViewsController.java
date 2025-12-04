package com.musicfly.backend.controllers;

import com.musicfly.backend.models.DAO.User;
import com.musicfly.backend.models.UserOptionsUUID;
import com.musicfly.backend.repositories.UserRepository;
import com.musicfly.backend.services.RedisTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class CoreViewsController {

    @Value("${app.domain.frontend}")
    public String domainFrontend;

    private final RedisTokenService redisTokenService;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncorer;

    private final static String ERROR_MSG = "error";

    @GetMapping("core/views/register/success")
    public ModelAndView showSuccessView() {
        String frontendUrl = domainFrontend+"login";
        ModelAndView modelAndView = new ModelAndView("email/register_ok");
        modelAndView.addObject("frontendURL", frontendUrl);
        return modelAndView;
    }

    @GetMapping("core/views/verified/success")
    public ModelAndView showSuccessVerifiedView() {
        String frontendUrl = domainFrontend+"login";
        ModelAndView modelAndView = new ModelAndView("email/verified_ok");
        modelAndView.addObject("frontendURL", frontendUrl);
        return modelAndView;
    }

    @GetMapping("core/views/code-verified")
    public String mostrarFormularioVerificacion(Model model) {
        return "email/code-verified";
    }

    @PostMapping("core/views/code-verified")
    public String verificarCodigo(@RequestParam String codigo, HttpSession session, Model model) {
        String username;

        if (codigo != null) {
            if(redisTokenService.hasTokenType(UserOptionsUUID.RESET_PASSWORD,codigo)){
                username = redisTokenService.getValueForKey(UserOptionsUUID.RESET_PASSWORD,codigo);
                return "redirect:/core/views/password-reset-form?username=" + username + "&passwordResetToken=" + codigo;
            }
        }
        
        model.addAttribute(ERROR_MSG, "El código ingresado no es válido.");
        return "email/code-verified";

    }

    @GetMapping("core/views/password-reset-form")
    public String mostrarFormulario(@RequestParam(required = false) String passwordResetToken,
                                    @RequestParam(required = false) String username,
                                    Model model) {
        if (passwordResetToken != null) {
            model.addAttribute("passwordResetToken", passwordResetToken);
        }
        if (username != null) {
            model.addAttribute("username", username);
        }
        return "email/password-reset-form";
    }

    @PostMapping("core/views/password-reset-form")
    public String procesarFormulario(
            @RequestParam String username,
            @RequestParam String actual,
            @RequestParam String nueva,
            @RequestParam String confirmar,
            @RequestParam String passwordResetToken,
            HttpServletRequest request,
            Model model) {

                Optional<User> user = userRepository.findByUsername(username);

                if (!nueva.equals(confirmar)) {
                    model.addAttribute(ERROR_MSG, "Las contraseñas no coinciden.");
                    return "email/password-reset-form";
                }

                if (redisTokenService.hasTokenType(UserOptionsUUID.RESET_PASSWORD,passwordResetToken)) {
                    if(user.isPresent()) {
                            redisTokenService.deleteToken(UserOptionsUUID.RESET_PASSWORD,passwordResetToken);
                            user.get().setPassword(passwordEncorer.encode(nueva));
                            userRepository.save(user.get());
                            model.addAttribute("success", "Contraseña actualizada correctamente.");
                            return "email/password-reset-form";
                    }
                }

            model.addAttribute(ERROR_MSG, "Solicitud inválida o expirada.");
            return "email/password-reset-form";
    }

}
