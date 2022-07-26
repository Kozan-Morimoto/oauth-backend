import express from 'express'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import cors from 'cors'
import session from 'express-session'
import passport from 'passport'
const GoogleStrategy = require('passport-google-oauth20').Strategy
const GithubStrategy = require('passport-github').Strategy

dotenv.config()

const app = express()

mongoose.connect(
	`${process.env.START_MONGODB}${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}${process.env.END_MONGODB}`,
	{},
	() => {
		console.log('Connected to Mongoose')
	}
)

// Models
import User from './User'
import { IMongoDBUser } from './types'

// Middleware
app.use(express.json())
app.use(
	cors({
		origin: 'http://localhost:3000',
		credentials: true,
	})
)
app.use(
	session({
		secret: 'secret',
		saveUninitialized: true,
		resave: true,
	})
)
app.use(passport.initialize())
app.use(passport.session())
passport.serializeUser((user: IMongoDBUser, done: any) => {
	done(null, user._id) // <-- We only serialize the ID for safety
})
passport.deserializeUser((id: any, done: any) => {

	User.findById(id, (err: Error, doc: IMongoDBUser) => {
		return done(null, doc)
	})

	done(null, id)
})


passport.use(
	new GoogleStrategy(
		{
			clientID: `${process.env.GOOGLE_CLIENT_ID}`,
			clientSecret: `${process.env.GOOGLE_CLIENT_SECRET}`,
			callbackURL: '/auth/google/callback',
		},
		function (_: any, __: any, profile: any, cb: any) {
			User.findOne({ googleId: profile.id }, async (err: Error, doc: IMongoDBUser) => {
				if (err) {
					return cb(err, null)
				}

				if (!doc) {
					const newUser = new User({
						googleId: profile.id,
						username: profile.name.givenName,
					})

					await newUser.save()
					cb(null, newUser)
				}
				cb(null, doc)
			})
		}
	)
)
passport.use(
	new GithubStrategy(
		{
			clientID: `${process.env.GITHUB_CLIENT_ID}`,
			clientSecret: `${process.env.GITHUB_CLIENT_SECRET}`,
			callbackURL: '/auth/github/callback',
		},
		function (_: any, __: any, profile: any, cb: any) {
			User.findOne({ githubId: profile.id }, async (err: Error, doc: IMongoDBUser) => {
				if (err) {
					return cb(err, null)
				}

				if (!doc) {
					const newUser = new User({
						githubId: profile.id,
						username: profile.username,
					})

					await newUser.save()
					cb(null, newUser)
				}
				cb(null, doc)
			})
		}
	)
)

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }))
app.get(
	'/auth/google/callback',
	passport.authenticate('google', {
		failureRedirect: '/login',
	}),
	function (req, res) {
		res.redirect('http://localhost:3000')
	}
)
app.get('/auth/github', passport.authenticate('github'))

app.get(
	'/auth/github/callback',
	passport.authenticate('github', { failureRedirect: '/login' }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect('http://localhost:3000')
	}
)

app.get('/', (req, res) => {
	res.render('Hello world!')
})

app.get('/getUser', (req, res) => {
	res.send(req.user)
})

app.get('/auth/logout', (req, res, next) => {
	if (req.user) {
		req.logout((err) => {
			if (err) {return next(err)}
			res.send('done')
		})
	}
})

app.listen(process.env.PORT || 4000, () => {
	console.log('Server started')
})
