package com.musicfly.backend.config;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;
import com.musicfly.backend.models.DAO.Genre;
import com.musicfly.backend.models.GenreType;
import com.musicfly.backend.repositories.GenreRepository;

/**
 * Clase que se encarga de inicializar los géneros en la base de datos al iniciar la aplicación.
 * Utiliza el repositorio de géneros para guardar los géneros de tipo {@link GenreType} si aún no están presentes.
 */
@Component
public class GenreInitializer {

    private final GenreRepository genreRepository;

    /**
     * Constructor que inicializa el repositorio de géneros.
     *
     * @param genreRepository El repositorio de géneros que se utilizará para la búsqueda y creación de géneros.
     */
    public GenreInitializer(GenreRepository genreRepository) {
        this.genreRepository = genreRepository;
    }

    /**
     * Método que se ejecuta después de la construcción del componente, utilizando la anotación {@link PostConstruct}.
     * Se asegura de que todos los géneros definidos en {@link GenreType} estén presentes en la base de datos.
     * Si un género aún no existe, lo guarda utilizando el repositorio.
     */
    @PostConstruct
    public void initGenres() {
        for (GenreType genreType : GenreType.values()) {
            genreRepository.findByType(genreType)
                    .ifPresentOrElse(
                            g -> {}, // si existe, no hacer nada
                            () -> genreRepository.save(new Genre(genreType))
                    );
        }
    }
}
