DROP DATABASE IF EXISTS crictrack;
CREATE DATABASE crictrack;
USE crictrack;

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL UNIQUE,
  display_name VARCHAR(120) NOT NULL,
  password_hash CHAR(64) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE teams (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  city VARCHAR(120) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_teams_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT uq_team_name_per_user UNIQUE (user_id, name)
);

CREATE TABLE players (
  id INT PRIMARY KEY AUTO_INCREMENT,
  team_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  role VARCHAR(80) NOT NULL,
  runs INT NOT NULL DEFAULT 0,
  wickets INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_players_team FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);

CREATE TABLE matches (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  team1_id INT NOT NULL,
  team2_id INT NOT NULL,
  venue VARCHAR(200) NOT NULL,
  match_date DATE NOT NULL,
  status ENUM('upcoming', 'completed') NOT NULL DEFAULT 'upcoming',
  team1_score VARCHAR(60) NULL,
  team2_score VARCHAR(60) NULL,
  result_text VARCHAR(255) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_matches_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_matches_team1 FOREIGN KEY (team1_id) REFERENCES teams(id) ON DELETE CASCADE,
  CONSTRAINT fk_matches_team2 FOREIGN KEY (team2_id) REFERENCES teams(id) ON DELETE CASCADE,
  CONSTRAINT chk_different_teams CHECK (team1_id <> team2_id)
);

CREATE INDEX idx_teams_user_id ON teams(user_id);
CREATE INDEX idx_players_team_id ON players(team_id);
CREATE INDEX idx_matches_user_id ON matches(user_id);
CREATE INDEX idx_matches_team1_id ON matches(team1_id);
CREATE INDEX idx_matches_team2_id ON matches(team2_id);
CREATE INDEX idx_matches_date ON matches(match_date);
