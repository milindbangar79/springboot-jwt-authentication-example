package com.springboot.jwt;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.library.Architectures;
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SpringBootJWTAuthenticationApplicationArchitectureTest {

    @Test
    void givenControllerClasses_ShouldDependOnClassesInSecurityPackageClassesOnly(){
        JavaClasses javaClasses = new ClassFileImporter().importPackages("com.springboot.jwt");

        ArchRule archRule = classes()
                            .that()
                            .resideInAPackage("..controller..")
                            .should().onlyDependOnClassesThat()
                            .resideInAPackage("..security..");

        assertThrows(AssertionError.class, ()->archRule.check(javaClasses));
    }

    @Test
    void givenServiceClasses_ShouldDependOnRepositoryClassesOnly(){
        JavaClasses javaClasses = new ClassFileImporter().importPackages("com.springboot.jwt");

        ArchRule archRule = classes()
                .that()
                .resideInAPackage("..services..")
                .should().onlyDependOnClassesThat()
                .resideInAPackage("..repository..");
        assertThrows(AssertionError.class, ()->archRule.check(javaClasses));
    }

    @Test
    void givenControllerLayerClasses_thenCheckWithFrameworkDependenciesSuccess() {
        JavaClasses javaClasses = new ClassFileImporter().importPackages("com.springboot.jwt");

        ArchRule archRule = classes()
                .that()
                .resideInAPackage("..controller..")
                .should().onlyDependOnClassesThat()
                .resideInAnyPackage("..services..", "..repository..","..security..","..payloads..","..models..","..exception..","org.slf4j..","java..", "javax..", "org.springframework..");

        archRule.check(javaClasses);
    }

    /**
     * This is a failing test for a reason that Repository classes are referenced in Controller to hit database and get the information
     * The test can be made to work, but essentially this should be the concern of the Service class and not Controller
     * Will keep this test method for example perspective
     */
    @Test
    void givenApplicationClasses_thenNoLayerViolationsShouldExist() {

        JavaClasses javaClasses = new ClassFileImporter().importPackages("com.springboot.jwt");

        Architectures.LayeredArchitecture arch = layeredArchitecture()
                // Define layers
                .layer("Controller").definedBy("..controller..")
                .layer("Service").definedBy("..services..")
                .layer("Repository").definedBy("..repository..")
                // Add constraints
                .whereLayer("Controller").mayNotBeAccessedByAnyLayer()
                .whereLayer("Service").mayOnlyBeAccessedByLayers("Controller")
                .whereLayer("Repository").mayOnlyBeAccessedByLayers("Service");

        arch.check(javaClasses);
    }


}
