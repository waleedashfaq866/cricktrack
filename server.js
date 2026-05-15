const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { query } = require("./db");

const app = express();
const PORT = Number(process.env.PORT || 4000);
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DISPLAY_NAME_REGEX = /^[a-zA-Z][a-zA-Z0-9\s._'-]{1,119}$/;
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,100}$/;
const TEAM_NAME_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9\s.'&-]{1,79}$/;
const CITY_REGEX = /^[a-zA-Z][a-zA-Z\s.'-]{1,79}$/;
const PLAYER_NAME_REGEX = /^[a-zA-Z][a-zA-Z\s.'-]{1,79}$/;
const PLAYER_ROLES = new Set(["Batsman", "Bowler", "All Rounder", "Wicket Keeper"]);
const VENUE_REGEX = /^[a-zA-Z0-9][a-zA-Z0-9\s,.'()-]{2,199}$/;
const SCORE_REGEX = /^[0-9]{1,3}\/[0-9]{1,2}(\s\([0-9]{1,2}(\.[0-9])?\sov\))?$/i;

app.use(cors({ origin: FRONTEND_ORIGIN === "*" ? true : FRONTEND_ORIGIN }));
app.use(express.json());

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function toISODate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function normalizeString(value) {
  return String(value || "").trim();
}

function isNonNegativeInteger(value) {
  return Number.isInteger(Number(value)) && Number(value) >= 0;
}

function getAuthUserId(req, res) {
  const userId = Number(req.headers["x-user-id"]);
  if (!userId || !Number.isInteger(userId)) {
    res.status(401).json({ message: "Missing or invalid user context" });
    return null;
  }
  return userId;
}

app.get("/api/health", async (_req, res) => {
  res.json({ ok: true });
});

app.post("/api/auth/register", async (req, res) => {
  const { email, displayName, password } = req.body || {};
  if (!email || !displayName || !password) {
    return res.status(400).json({ message: "email, displayName and password are required" });
  }
  const normalizedEmail = normalizeString(email).toLowerCase();
  const normalizedDisplayName = normalizeString(displayName);
  if (!EMAIL_REGEX.test(normalizedEmail)) {
    return res.status(400).json({ message: "Invalid email format" });
  }
  if (!DISPLAY_NAME_REGEX.test(normalizedDisplayName)) {
    return res.status(400).json({ message: "Invalid display name format" });
  }
  if (!PASSWORD_REGEX.test(String(password))) {
    return res.status(400).json({ message: "Password must include uppercase, lowercase, number and be 8-100 chars" });
  }

  try {
    const existing = await query("SELECT id FROM users WHERE email = ? LIMIT 1", [normalizedEmail]);
    if (existing.length) {
      return res.status(409).json({ message: "Email already exists" });
    }

    const hashedPassword = hashPassword(password);
    const result = await query(
      "INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)",
      [normalizedEmail, normalizedDisplayName, hashedPassword]
    );

    return res.status(201).json({
      id: result.insertId,
      email: normalizedEmail,
      displayName: normalizedDisplayName
    });
  } catch (error) {
    return res.status(500).json({ message: "Failed to register user", error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ message: "email and password are required" });
  }
  const normalizedEmail = normalizeString(email).toLowerCase();
  if (!EMAIL_REGEX.test(normalizedEmail)) {
    return res.status(400).json({ message: "Invalid email format" });
  }
  if (String(password).length < 8 || String(password).length > 100) {
    return res.status(400).json({ message: "Invalid password length" });
  }

  try {
    const hashedPassword = hashPassword(password);
    const rows = await query(
      "SELECT id, email, display_name FROM users WHERE email = ? AND password_hash = ? LIMIT 1",
      [normalizedEmail, hashedPassword]
    );

    if (!rows.length) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    return res.json({
      user: {
        id: rows[0].id,
        email: rows[0].email,
        displayName: rows[0].display_name
      }
    });
  } catch (error) {
    return res.status(500).json({ message: "Failed to login", error: error.message });
  }
});

app.get("/api/teams", async (_req, res) => {
  const userId = getAuthUserId(_req, res);
  if (!userId) return;
  try {
    const rows = await query(
      `SELECT t.id, t.name, t.city, t.created_at, t.user_id,
              COUNT(p.id) AS player_count
       FROM teams t
       LEFT JOIN players p ON p.team_id = t.id
       WHERE t.user_id = ?
       GROUP BY t.id, t.name, t.city, t.created_at, t.user_id
       ORDER BY t.created_at DESC`
      ,
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch teams", error: error.message });
  }
});

app.post("/api/teams", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const { name, city } = req.body || {};
  if (!name || !city) {
    return res.status(400).json({ message: "name and city are required" });
  }
  const normalizedName = normalizeString(name);
  const normalizedCity = normalizeString(city);
  if (!TEAM_NAME_REGEX.test(normalizedName)) {
    return res.status(400).json({ message: "Invalid team name format" });
  }
  if (!CITY_REGEX.test(normalizedCity)) {
    return res.status(400).json({ message: "Invalid city format" });
  }

  try {
    const result = await query("INSERT INTO teams (user_id, name, city) VALUES (?, ?, ?)", [userId, normalizedName, normalizedCity]);
    const rows = await query(
      `SELECT t.id, t.name, t.city, t.created_at, t.user_id,
              COUNT(p.id) AS player_count
       FROM teams t
       LEFT JOIN players p ON p.team_id = t.id
       WHERE t.id = ? AND t.user_id = ?
       GROUP BY t.id, t.name, t.city, t.created_at, t.user_id`,
      [result.insertId, userId]
    );
    res.status(201).json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to create team", error: error.message });
  }
});

app.put("/api/teams/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const id = Number(req.params.id);
  const { name, city } = req.body || {};
  if (!id || !name || !city) {
    return res.status(400).json({ message: "valid id, name and city are required" });
  }
  const normalizedName = normalizeString(name);
  const normalizedCity = normalizeString(city);
  if (!TEAM_NAME_REGEX.test(normalizedName)) {
    return res.status(400).json({ message: "Invalid team name format" });
  }
  if (!CITY_REGEX.test(normalizedCity)) {
    return res.status(400).json({ message: "Invalid city format" });
  }

  try {
    const result = await query("UPDATE teams SET name = ?, city = ? WHERE id = ? AND user_id = ?", [normalizedName, normalizedCity, id, userId]);
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Team not found" });
    }

    const rows = await query(
      `SELECT t.id, t.name, t.city, t.created_at, t.user_id,
              COUNT(p.id) AS player_count
       FROM teams t
       LEFT JOIN players p ON p.team_id = t.id
       WHERE t.id = ? AND t.user_id = ?
       GROUP BY t.id, t.name, t.city, t.created_at, t.user_id`,
      [id, userId]
    );
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to update team", error: error.message });
  }
});

app.delete("/api/teams/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ message: "valid id is required" });
  }

  try {
    const result = await query("DELETE FROM teams WHERE id = ? AND user_id = ?", [id, userId]);
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Team not found" });
    }
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: "Failed to delete team", error: error.message });
  }
});

app.get("/api/teams/:id/players", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const teamId = Number(req.params.id);
  if (!teamId) {
    return res.status(400).json({ message: "valid team id is required" });
  }

  try {
    const teamRows = await query("SELECT id FROM teams WHERE id = ? AND user_id = ? LIMIT 1", [teamId, userId]);
    if (!teamRows.length) {
      return res.status(404).json({ message: "Team not found" });
    }
    const rows = await query(
      `SELECT id, team_id, name, role, runs, wickets, created_at
       FROM players
       WHERE team_id = ?
       ORDER BY created_at DESC`,
      [teamId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch players", error: error.message });
  }
});

app.post("/api/teams/:id/players", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const teamId = Number(req.params.id);
  const { name, role, runs, wickets } = req.body || {};
  if (!teamId || !name || !role) {
    return res.status(400).json({ message: "valid team id, name and role are required" });
  }
  const normalizedName = normalizeString(name);
  const normalizedRole = normalizeString(role);
  const parsedRuns = Number(runs || 0);
  const parsedWickets = Number(wickets || 0);
  if (!PLAYER_NAME_REGEX.test(normalizedName)) {
    return res.status(400).json({ message: "Invalid player name format" });
  }
  if (!PLAYER_ROLES.has(normalizedRole)) {
    return res.status(400).json({ message: "Invalid player role" });
  }
  if (!isNonNegativeInteger(parsedRuns) || parsedRuns > 50000) {
    return res.status(400).json({ message: "Invalid runs value" });
  }
  if (!isNonNegativeInteger(parsedWickets) || parsedWickets > 2000) {
    return res.status(400).json({ message: "Invalid wickets value" });
  }

  try {
    const teamRows = await query("SELECT id FROM teams WHERE id = ? AND user_id = ? LIMIT 1", [teamId, userId]);
    if (!teamRows.length) {
      return res.status(404).json({ message: "Team not found" });
    }
    const result = await query(
      "INSERT INTO players (team_id, name, role, runs, wickets) VALUES (?, ?, ?, ?, ?)",
      [teamId, normalizedName, normalizedRole, parsedRuns, parsedWickets]
    );
    const rows = await query("SELECT * FROM players WHERE id = ? LIMIT 1", [result.insertId]);
    res.status(201).json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to add player", error: error.message });
  }
});

app.delete("/api/players/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const id = Number(req.params.id);
  if (!id) {
    return res.status(400).json({ message: "valid player id is required" });
  }

  try {
    const result = await query(
      `DELETE p FROM players p
       JOIN teams t ON t.id = p.team_id
       WHERE p.id = ? AND t.user_id = ?`,
      [id, userId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Player not found" });
    }
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: "Failed to delete player", error: error.message });
  }
});

app.put("/api/players/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const id = Number(req.params.id);
  const { name, role, runs, wickets } = req.body || {};
  if (!id || !name || !role) {
    return res.status(400).json({ message: "valid player id, name and role are required" });
  }
  const normalizedName = normalizeString(name);
  const normalizedRole = normalizeString(role);
  const parsedRuns = Number(runs || 0);
  const parsedWickets = Number(wickets || 0);
  if (!PLAYER_NAME_REGEX.test(normalizedName)) {
    return res.status(400).json({ message: "Invalid player name format" });
  }
  if (!PLAYER_ROLES.has(normalizedRole)) {
    return res.status(400).json({ message: "Invalid player role" });
  }
  if (!isNonNegativeInteger(parsedRuns) || parsedRuns > 50000) {
    return res.status(400).json({ message: "Invalid runs value" });
  }
  if (!isNonNegativeInteger(parsedWickets) || parsedWickets > 2000) {
    return res.status(400).json({ message: "Invalid wickets value" });
  }

  try {
    const ownerRows = await query(
      `SELECT p.id
       FROM players p
       JOIN teams t ON t.id = p.team_id
       WHERE p.id = ? AND t.user_id = ?
       LIMIT 1`,
      [id, userId]
    );
    if (!ownerRows.length) {
      return res.status(404).json({ message: "Player not found" });
    }
    const result = await query(
      "UPDATE players SET name = ?, role = ?, runs = ?, wickets = ? WHERE id = ?",
      [normalizedName, normalizedRole, parsedRuns, parsedWickets, id]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Player not found" });
    }
    const rows = await query("SELECT * FROM players WHERE id = ? LIMIT 1", [id]);
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to update player", error: error.message });
  }
});

app.get("/api/matches", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const limit = Number(req.query.limit || 10);
  const cappedLimit = Number.isFinite(limit) && limit > 0 ? Math.min(limit, 50) : 10;

  try {
    const rows = await query(
      `SELECT m.id, m.match_date, m.venue, m.status, m.team1_score, m.team2_score, m.result_text, m.created_at,
              t1.id AS team1_id, t1.name AS team1_name,
              t2.id AS team2_id, t2.name AS team2_name
       FROM matches m
       JOIN teams t1 ON t1.id = m.team1_id
       JOIN teams t2 ON t2.id = m.team2_id
       WHERE m.user_id = ?
       ORDER BY m.match_date DESC, m.id DESC
       LIMIT ${cappedLimit}`,
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch matches", error: error.message });
  }
});

app.post("/api/matches", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const { team1Id, team2Id, venue, matchDate, status, team1Score, team2Score, resultText } = req.body || {};
  const parsedTeam1Id = Number(team1Id);
  const parsedTeam2Id = Number(team2Id);
  const parsedDate = toISODate(matchDate);
  const normalizedVenue = normalizeString(venue);
  const normalizedStatus = normalizeString(status || "upcoming");
  const normalizedTeam1Score = normalizeString(team1Score);
  const normalizedTeam2Score = normalizeString(team2Score);
  const normalizedResultText = normalizeString(resultText);

  if (!parsedTeam1Id || !parsedTeam2Id || parsedTeam1Id === parsedTeam2Id || !normalizedVenue || !parsedDate) {
    return res.status(400).json({
      message: "team1Id, team2Id, venue, and matchDate are required; teams must be different"
    });
  }
  if (!VENUE_REGEX.test(normalizedVenue)) {
    return res.status(400).json({ message: "Invalid venue format" });
  }
  if (!["upcoming", "completed"].includes(normalizedStatus)) {
    return res.status(400).json({ message: "Invalid match status" });
  }
  if (normalizedStatus === "completed") {
    if (!SCORE_REGEX.test(normalizedTeam1Score) || !SCORE_REGEX.test(normalizedTeam2Score)) {
      return res.status(400).json({ message: "Invalid score format for completed match" });
    }
    if (!normalizedResultText || normalizedResultText.length < 6 || normalizedResultText.length > 255) {
      return res.status(400).json({ message: "Result text must be 6-255 chars for completed match" });
    }
  }
  if (normalizedTeam1Score && !SCORE_REGEX.test(normalizedTeam1Score)) {
    return res.status(400).json({ message: "Invalid team1 score format" });
  }
  if (normalizedTeam2Score && !SCORE_REGEX.test(normalizedTeam2Score)) {
    return res.status(400).json({ message: "Invalid team2 score format" });
  }

  try {
    const teamsRows = await query(
      "SELECT id FROM teams WHERE user_id = ? AND id IN (?, ?)",
      [userId, parsedTeam1Id, parsedTeam2Id]
    );
    if (teamsRows.length !== 2) {
      return res.status(400).json({ message: "Both teams must belong to current user" });
    }
    const insertResult = await query(
      `INSERT INTO matches
       (user_id, team1_id, team2_id, venue, match_date, status, team1_score, team2_score, result_text)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        parsedTeam1Id,
        parsedTeam2Id,
        normalizedVenue,
        parsedDate,
        normalizedStatus,
        normalizedTeam1Score || null,
        normalizedTeam2Score || null,
        normalizedResultText || null
      ]
    );

    const rows = await query(
      `SELECT m.id, m.match_date, m.venue, m.status, m.team1_score, m.team2_score, m.result_text, m.created_at,
              t1.id AS team1_id, t1.name AS team1_name,
              t2.id AS team2_id, t2.name AS team2_name
       FROM matches m
       JOIN teams t1 ON t1.id = m.team1_id
       JOIN teams t2 ON t2.id = m.team2_id
       WHERE m.id = ? AND m.user_id = ?`,
      [insertResult.insertId, userId]
    );
    res.status(201).json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to create match", error: error.message });
  }
});

app.put("/api/matches/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const matchId = Number(req.params.id);
  const { team1Id, team2Id, venue, matchDate, status, team1Score, team2Score, resultText } = req.body || {};
  const parsedTeam1Id = Number(team1Id);
  const parsedTeam2Id = Number(team2Id);
  const parsedDate = toISODate(matchDate);
  const normalizedVenue = normalizeString(venue);
  const normalizedStatus = normalizeString(status || "upcoming");
  const normalizedTeam1Score = normalizeString(team1Score);
  const normalizedTeam2Score = normalizeString(team2Score);
  const normalizedResultText = normalizeString(resultText);

  if (!matchId || !parsedTeam1Id || !parsedTeam2Id || parsedTeam1Id === parsedTeam2Id || !normalizedVenue || !parsedDate) {
    return res.status(400).json({
      message: "valid match id, team1Id, team2Id, venue, and matchDate are required; teams must be different"
    });
  }
  if (!VENUE_REGEX.test(normalizedVenue)) {
    return res.status(400).json({ message: "Invalid venue format" });
  }
  if (!["upcoming", "completed"].includes(normalizedStatus)) {
    return res.status(400).json({ message: "Invalid match status" });
  }
  if (normalizedStatus === "completed") {
    if (!SCORE_REGEX.test(normalizedTeam1Score) || !SCORE_REGEX.test(normalizedTeam2Score)) {
      return res.status(400).json({ message: "Invalid score format for completed match" });
    }
    if (!normalizedResultText || normalizedResultText.length < 6 || normalizedResultText.length > 255) {
      return res.status(400).json({ message: "Result text must be 6-255 chars for completed match" });
    }
  }
  if (normalizedTeam1Score && !SCORE_REGEX.test(normalizedTeam1Score)) {
    return res.status(400).json({ message: "Invalid team1 score format" });
  }
  if (normalizedTeam2Score && !SCORE_REGEX.test(normalizedTeam2Score)) {
    return res.status(400).json({ message: "Invalid team2 score format" });
  }

  try {
    const ownerRows = await query("SELECT id FROM matches WHERE id = ? AND user_id = ? LIMIT 1", [matchId, userId]);
    if (!ownerRows.length) {
      return res.status(404).json({ message: "Match not found" });
    }

    const teamsRows = await query(
      "SELECT id FROM teams WHERE user_id = ? AND id IN (?, ?)",
      [userId, parsedTeam1Id, parsedTeam2Id]
    );
    if (teamsRows.length !== 2) {
      return res.status(400).json({ message: "Both teams must belong to current user" });
    }

    const result = await query(
      `UPDATE matches
       SET team1_id = ?, team2_id = ?, venue = ?, match_date = ?, status = ?, team1_score = ?, team2_score = ?, result_text = ?
       WHERE id = ? AND user_id = ?`,
      [
        parsedTeam1Id,
        parsedTeam2Id,
        normalizedVenue,
        parsedDate,
        normalizedStatus,
        normalizedTeam1Score || null,
        normalizedTeam2Score || null,
        normalizedResultText || null,
        matchId,
        userId
      ]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Match not found" });
    }

    const rows = await query(
      `SELECT m.id, m.match_date, m.venue, m.status, m.team1_score, m.team2_score, m.result_text, m.created_at,
              t1.id AS team1_id, t1.name AS team1_name,
              t2.id AS team2_id, t2.name AS team2_name
       FROM matches m
       JOIN teams t1 ON t1.id = m.team1_id
       JOIN teams t2 ON t2.id = m.team2_id
       WHERE m.id = ? AND m.user_id = ?`,
      [matchId, userId]
    );
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: "Failed to update match", error: error.message });
  }
});

app.delete("/api/matches/:id", async (req, res) => {
  const userId = getAuthUserId(req, res);
  if (!userId) return;
  const matchId = Number(req.params.id);
  if (!matchId) {
    return res.status(400).json({ message: "valid match id is required" });
  }

  try {
    const result = await query("DELETE FROM matches WHERE id = ? AND user_id = ?", [matchId, userId]);
    if (!result.affectedRows) {
      return res.status(404).json({ message: "Match not found" });
    }
    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: "Failed to delete match", error: error.message });
  }
});

app.get("/api/dashboard/summary", async (_req, res) => {
  const userId = getAuthUserId(_req, res);
  if (!userId) return;
  try {
    const [teamsCountRows, playersCountRows, matchesCountRows, completedCountRows] = await Promise.all([
      query("SELECT COUNT(*) AS count FROM teams WHERE user_id = ?", [userId]),
      query(
        `SELECT COUNT(*) AS count
         FROM players p
         JOIN teams t ON t.id = p.team_id
         WHERE t.user_id = ?`,
        [userId]
      ),
      query("SELECT COUNT(*) AS count FROM matches WHERE user_id = ?", [userId]),
      query("SELECT COUNT(*) AS count FROM matches WHERE user_id = ? AND status = 'completed'", [userId])
    ]);

    res.json({
      totalTeams: teamsCountRows[0].count,
      totalPlayers: playersCountRows[0].count,
      totalMatches: matchesCountRows[0].count,
      completedMatches: completedCountRows[0].count
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch dashboard summary", error: error.message });
  }
});

app.use((err, _req, res, _next) => {
  res.status(500).json({ message: "Unexpected server error", error: err.message });
});

app.listen(PORT, () => {
  console.log(`CrickTrack API running on port ${PORT}`);
});
