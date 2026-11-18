package com.example.demo;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.example.demo.model.AppUser;
import com.example.demo.model.Comment;
import com.example.demo.model.Image;
import com.example.demo.model.Producto;
import com.example.demo.repo.appUserRepo;
import com.example.demo.repo.categoriaRepo;
import com.example.demo.repo.comentarioRepo;
import com.example.demo.repo.imagenRepo;
import com.example.demo.repo.productoRepo;
import com.example.demo.service.JwtTokenService;

@SpringBootTest
@AutoConfigureMockMvc
class ApiSecurityAndDtoTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private productoRepo productoRepo;

    @MockBean
    private categoriaRepo categoriaRepo;

    @MockBean
    private comentarioRepo comentarioRepo;

    @MockBean
    private imagenRepo imagenRepo;

    @MockBean
    private appUserRepo appUserRepo;

    private static final String PRODUCTO_JSON = """
            {"nombre":"Cafe","descripcion":"Molido","lote":"L1",
             "precioUnitario":12.5,"fechaCaducidad":"2026-12-31"}
            """;

    private static final String COMENTARIO_JSON = """
            {"username":"dana","comentario_corto":"Bueno","estrellas":4}
            """;

    private static final String IMAGEN_JSON = """
            {"url":"https://example.com/foto.png","prioridad":1,"tamanio":"grande","responsiva":true}
            """;

    @BeforeEach
    void prepararRepositoriosVacios() {
        when(productoRepo.findAll()).thenReturn(List.of());
        when(categoriaRepo.findAll()).thenReturn(List.of());
        when(comentarioRepo.findAll()).thenReturn(List.of());
        when(imagenRepo.findAll()).thenReturn(List.of());
    }

    private String tokenConRoles(String... roles) {
        List<SimpleGrantedAuthority> authorities = List.of(roles).stream()
                .map(rol -> new SimpleGrantedAuthority("ROLE_" + rol))
                .toList();
        return jwtTokenService.createToken(
                new UsernamePasswordAuthenticationToken("dana", "n/a", authorities));
    }

    @Test
    void todasLasLecturasFuncionanSinToken() throws Exception {
        for (String ruta : List.of("/productos", "/categorias", "/comentarios", "/imagenes")) {
            mockMvc.perform(get(ruta))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$").isArray());
        }

        for (String ruta : List.of(
                "/producto/inexistente", "/categoria/inexistente",
                "/comentario/inexistente", "/imagen/inexistente",
                "/comentarios/inexistente", "/categoria/producto/inexistente",
                "/imagenes/producto/inexistente")) {
            mockMvc.perform(get(ruta)).andExpect(status().isNotFound());
        }
    }

    @Test
    void escribirProductoSinTokenDevuelve401() throws Exception {
        mockMvc.perform(post("/producto")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(PRODUCTO_JSON))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unUsuarioNoPuedeEscribirProductosNiCategorias() throws Exception {
        String token = tokenConRoles("USER");

        mockMvc.perform(post("/producto")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(PRODUCTO_JSON))
                .andExpect(status().isForbidden());
    }

    @Test
    void unUsuarioSiPuedeEscribirComentariosEImagenes() throws Exception {
        when(comentarioRepo.save(any(Comment.class))).thenAnswer(invocacion -> {
            Comment guardado = invocacion.getArgument(0);
            guardado.setId("c-1");
            return guardado;
        });
        when(imagenRepo.save(any(Image.class))).thenAnswer(invocacion -> {
            Image guardado = invocacion.getArgument(0);
            guardado.setId("i-1");
            return guardado;
        });

        String token = tokenConRoles("USER");

        mockMvc.perform(post("/comentario")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(COMENTARIO_JSON))
                .andExpect(status().isCreated())
                .andExpect(header().exists("Location"));

        mockMvc.perform(post("/imagen")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(IMAGEN_JSON))
                .andExpect(status().isCreated());
    }

    @Test
    void crearProductoConAdminDevuelve201YLocation() throws Exception {
        when(productoRepo.save(any(Producto.class))).thenAnswer(invocacion -> {
            Producto guardado = invocacion.getArgument(0);
            guardado.setId("p-1");
            return guardado;
        });

        mockMvc.perform(post("/producto")
                        .header("Authorization", "Bearer " + tokenConRoles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(PRODUCTO_JSON))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", "/producto/p-1"))
                .andExpect(jsonPath("$.id").value("p-1"));
    }

    @Test
    void elRegistroSiempreCreaRolUser() throws Exception {
        when(appUserRepo.findByUsername("dana")).thenReturn(Optional.empty());
        when(appUserRepo.save(any(AppUser.class))).thenAnswer(invocacion -> {
            AppUser guardado = invocacion.getArgument(0);
            guardado.setId("u-1");
            return guardado;
        });

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"dana","password":"clave-segura-123","role":"ADMIN"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void elLoginEmiteJwtYRechazaCredencialesInvalidas() throws Exception {
        when(appUserRepo.findByUsername("dana")).thenReturn(Optional.of(
                new AppUser("dana", passwordEncoder.encode("clave-segura-123"), "USER")));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"dana","password":"clave-segura-123"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"));

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"dana","password":"equivocada"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unDtoInvalidoDevuelve400() throws Exception {
        mockMvc.perform(post("/producto")
                        .header("Authorization", "Bearer " + tokenConRoles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"nombre":"","descripcion":"","lote":"","precioUnitario":-1}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void elPatchCambiaSoloLosCamposEnviados() throws Exception {
        Producto existente = Producto.builder()
                .id("p-1")
                .nombre("Cafe")
                .descripcion("Molido")
                .lote("L1")
                .precioUnitario(12.5f)
                .fechaCaducidad(LocalDate.of(2026, 12, 31))
                .build();

        when(productoRepo.findById("p-1")).thenReturn(Optional.of(existente));
        when(productoRepo.save(any(Producto.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        mockMvc.perform(patch("/producto/p-1")
                        .header("Authorization", "Bearer " + tokenConRoles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"nombre":"Cafe nuevo"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.nombre").value("Cafe nuevo"))
                .andExpect(jsonPath("$.descripcion").value("Molido"))
                .andExpect(jsonPath("$.lote").value("L1"));

        mockMvc.perform(patch("/producto/p-1")
                        .header("Authorization", "Bearer " + tokenConRoles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(patch("/producto/inexistente")
                        .header("Authorization", "Bearer " + tokenConRoles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"nombre":"Otro"}
                                """))
                .andExpect(status().isNotFound());
    }

    @Test
    void openApiPublicaElEsquemaBearer() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth").exists())
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"));
    }
}
