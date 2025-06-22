package org.owasp.webgoat.lessons.pathtraversal;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.WebSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.FileSystemUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import java.net.URI;

@AllArgsConstructor
@Getter
public class ProfileUploadBase extends AssignmentEndpoint {

  private String webGoatHomeDirectory;
  private WebSession webSession;

  protected AttackResult execute(MultipartFile file, String fullName) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser();

    try {
      ensurePathIsRelative(fullName);
      var uploadedFile = new File(uploadDirectory, fullName);
      uploadedFile.createNewFile();
      FileCopyUtils.copy(file.getBytes(), uploadedFile);

      if (attemptWasMade(uploadDirectory, uploadedFile)) {
        return solvedIt(uploadedFile);
      }
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getAbsoluteFile())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  private static void ensurePathIsRelative(String path) {
    ensurePathIsRelative(new File(path));
  }


  private static void ensurePathIsRelative(URI uri) {
    ensurePathIsRelative(new File(uri));
  }


  private static void ensurePathIsRelative(File file) {
    // Based on https://stackoverflow.com/questions/2375903/whats-the-best-way-to-defend-against-a-path-traversal-attack/34658355#34658355
    String canonicalPath;
    String absolutePath;
  
    if (file.isAbsolute()) {
      throw new RuntimeException("Potential directory traversal attempt - absolute path not allowed");
    }
  
    try {
      canonicalPath = file.getCanonicalPath();
      absolutePath = file.getAbsolutePath();
    } catch (IOException e) {
      throw new RuntimeException("Potential directory traversal attempt", e);
    }
  
    if (!canonicalPath.startsWith(absolutePath) || !canonicalPath.equals(absolutePath)) {
      throw new RuntimeException("Potential directory traversal attempt");
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser() {
    var uploadDirectory =
        new File(this.webGoatHomeDirectory, "/PathTraversal/" + webSession.getUserName());
    if (uploadDirectory.exists()) {
      FileSystemUtils.deleteRecursively(uploadDirectory);
    }
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  private boolean attemptWasMade(File expectedUploadDirectory, File uploadedFile)
      throws IOException {
    return !expectedUploadDirectory
        .getCanonicalPath()
        .equals(uploadedFile.getParentFile().getCanonicalPath());
  }

  private AttackResult solvedIt(File uploadedFile) throws IOException {
    if (uploadedFile.getCanonicalFile().getParentFile().getName().endsWith("PathTraversal")) {
      return success(this).build();
    }
    return failed(this)
        .attemptWasMade()
        .feedback("path-traversal-profile-attempt")
        .feedbackArgs(uploadedFile.getCanonicalPath())
        .build();
  }

  public ResponseEntity<?> getProfilePicture() {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64());
  }

  protected byte[] getProfilePictureAsBase64() {
    var profilePictureDirectory =
        new File(this.webGoatHomeDirectory, "/PathTraversal/" + webSession.getUserName());
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(profileDirectoryFiles[0])) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
