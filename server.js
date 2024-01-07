const express = require('express');
require('dotenv').config();
const app = express();
const { Datastore, PropertyFilter } = require('@google-cloud/datastore');
const { default: axios } = require('axios');
const { auth } = require('express-openid-connect');
const { requiresAuth } = require('express-openid-connect');
var jwt = require('jsonwebtoken');


// auth0 config information
const config = {
    authRequired: false,
    auth0Logout: true,
    baseURL: process.env.AUTH0_URL,
    clientID: process.env.AUTH0_CLIENT_ID,
    issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
    secret: process.env.AUTH0_CONFIG_SECRET
}

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

app.use(express.json());

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Example app listening on port ${PORT}`)
})

const datastore = new Datastore({
    projectId: 'portfolio-407508',
    keyFilename: 'portfolio-407508-2b1c28cceafd.json',
});

// URL variable for SELF properties
const app_url = process.env.AUTH0_URL;

// The welcome page (link for user login)
app.get('/', (req, res) => {
    const isAuthenticated = req.oidc.isAuthenticated();

    if (isAuthenticated) {
        res.redirect('/callafter')
    } else {
        res.send(`<a href="/login">Login here</a>`)
    }
});

// Creates a new user account in DB on callback
app.get('/callafter', async (req, res) => {
    const isAuthenticated = req.oidc.isAuthenticated();

    if (isAuthenticated) {
        const userId = req.oidc.user.sub;
        const createdAt = req.oidc.user.updated_at;
        const email = req.oidc.user.email;

        const query = datastore.createQuery('Users').filter(new PropertyFilter('sub', '=', req.oidc.user.sub));
        const [entity] = await datastore.runQuery(query);

        if (entity.length === 0) {
            const userEntity = {
                key: datastore.key(['Users', userId]),
                data: {
                    sub: userId,
                    email: email,
                    time_created: createdAt
                }
            };

            await datastore.upsert(userEntity);
        }
        res.redirect('/profile');
    }
    else {
        res.redirect('/');
    }
})

// Displays the JWT for the user
app.get('/profile', requiresAuth(), (req, res) => {
    res.send(req.oidc.idToken);
});

// Create an aircraft entity
app.post('/aircraft', async (req, res) => {
    const { type, capacity, registration } = req.body;

    // Check for valid JWT
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);
    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    // Create aircraft entity
    if (type !== undefined && capacity !== undefined && registration !== undefined) {

        if (typeof (type) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }

        if (typeof (capacity) !== 'number') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }

        if (typeof (registration) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }

        try {
            const aircraftEntity = {
                key: datastore.key('Aircraft'),
                data: {
                    type: type,
                    capacity: capacity,
                    registration: registration,
                    cans: [],
                    owner: sub
                }
            }

            await datastore.upsert(aircraftEntity);

            const id = aircraftEntity.key.id;
            aircraftEntity.data.self = `${app_url}/aircraft/${id}`;

            await datastore.upsert(aircraftEntity);

            res.status(201).json({
                id: parseInt(id),
                type: type,
                capacity: capacity,
                registration: registration,
                cans: [],
                owner: sub,
                self: aircraftEntity.data.self,
            });

        }
        catch (error) {
            console.log(error)
            res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' });
        }
    }
    else {
        return res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' });
    }
})

// View an aircraft (GET)
app.get('/aircraft/:aircraft_id', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    // Check for invalid Accept header MIME type
    if (req.headers['accept'] && req.headers['accept'] !== '*/*' && !req.headers['accept'].includes('application/json') && !req.headers['accept'].includes('text/html')) {
        return res.status(406).json({ 'Error': 'Endpoint does not support that MIME type for header Accept (supported types: application/json, text/html)' });
    }

    // Check for invalid Content-Type header MIME type
    if (req.headers['content-type'] && req.headers['content-type'] !== '*/*' && !req.headers['content-type'].includes('application/json') && !req.headers['content-type'].includes('text/html')) {
        return res.status(415).json({ 'Error': 'Endpoint does not support that MIME type for header Content-Type (supported types: application/json, text/html)' });
    }

    try {
        const query = datastore.createQuery('Aircraft').filter(new PropertyFilter('__key__', '=', datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)])));
        const [entity] = await datastore.runQuery(query);

        // Check if sub matches with aircraft owner
        if (sub !== entity[0].owner) {
            return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
        }

        if (entity.length > 0) {
            const aircraftData = {
                id: parseInt(req.params.aircraft_id, 10),
                type: entity[0].type,
                capacity: entity[0].capacity,
                registration: entity[0].registration,
                cans: entity[0].cans,
                owner: entity[0].owners,
                self: entity[0].self,
            }

            // Return with HTML
            if (req.headers['accept'] === 'text/html') {
                return res.status(200).send(`<html><ul><li>Type: ${aircraftData.type}</li><li>Capacity: ${aircraftData.capacity}</li><li>Registration: ${aircraftData.registration}</li></ul></html>`);
            }

            // Return with json (default)
            else {
                return res.status(200).json(aircraftData);
            }

        }
        else {
            res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' })
        }

    } catch (error) {
        res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
    }
})

// List all Aircraft (GET)
app.get('/aircraft', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    try {

        // Grab query params for offset from url
        const limitParam = parseInt(req.query.limit);
        const offsetParam = parseInt(req.query.page);

        let limit = 5
        if (!isNaN(limitParam)) {
            limit = limitParam
        }

        let offset = 0
        if (!isNaN(offsetParam)) {
            offset = (offsetParam - 1) * limit
        }

        // Generate link for next page
        let newOffset = null;
        if (offsetParam === 0 || isNaN(offsetParam)) {
            newOffset = 2;
        } else {
            newOffset = offsetParam + 1;
        }
        let nextPageLink = `/aircraft/?limit=${limit}&page=${newOffset}`

        const query = datastore.createQuery('Aircraft').filter(new PropertyFilter('owner', '=', sub)).limit(limit).offset(offset);
        const [entities] = await datastore.runQuery(query);

        // Check if this is the last page
        const queryNext = datastore.createQuery('Aircraft').filter(new PropertyFilter('owner', '=', sub)).limit(limit).offset(offset + limit)
        const [nextEntity] = await datastore.runQuery(queryNext);
        if (nextEntity.length <= 0) {
            nextPageLink = null;
        }

        if (nextPageLink !== null) {
            aircraftData = {
                offset: offset,
                limit: limit,
                aircraft: [],
                next: nextPageLink,
            }
        } else {
            aircraftData = {
                offset: offset,
                limit: limit,
                aircraft: [],
            }
        }

        if (entities.length > 0) {
            for (i = 0; i < entities.length; i++) {
                dataForAircraft = {
                    id: entities[i][datastore.KEY].id,
                    type: entities[i].type,
                    capacity: entities[i].capacity,
                    registration: entities[i].registration,
                    cans: entities[i].cans,
                    owner: entities[i].owner,
                    self: entities[i].self,
                }
                aircraftData.aircraft.push(dataForAircraft);
            }
        }

        res.status(200).json(aircraftData);
    }
    catch (error) {
        res.status(404).json({ error: error.message });
    }
})

// Edit an Aircraft (PATCH)
app.patch('/aircraft/:aircraft_id', async (req, res) => {
    const { type, capacity, registration } = req.body;

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    // Check for invalid Accept header MIME type
    if (req.headers['accept'] !== '*/*' && !req.headers['accept'].includes('application/json')) {
        return res.status(406).json({ 'Error': 'Endpoint does not support that MIME type for header Accept (supported types: applications/json)' })
    }

    // Check for invalid Content-Type header MIME type
    if (req.headers['content-type'] !== '*/*' && !req.headers['content-type'].includes('application/json')) {
        return res.status(415).json({ 'Error': 'Endpoint does not support that MIME type for header Content-Type (supported types: applications/json)' })
    }

    if (type !== undefined) {
        if (typeof (type) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    if (capacity !== undefined) {
        if (typeof (capacity) !== 'number') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    if (registration !== undefined) {
        if (typeof (registration) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    // Query the current information for the aircraft
    const query = datastore.createQuery('Aircraft').filter(new PropertyFilter('__key__', '=', datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)])));
    const [entity] = await datastore.runQuery(query);

    if (entity.length < 1) {
        return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
    }

    // Check if sub matches with aircraft owner
    if (sub !== entity[0].owner) {
        return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
    }

    let newType = entity[0].type;
    let newCapacity = entity[0].capacity;
    let newRegistration = entity[0].registration;
    let newCans = entity[0].cans;
    let newOwner = entity[0].owner;
    let newSelf = entity[0].self;

    if (type !== undefined) {
        newType = type;
    }
    if (capacity !== undefined) {
        newCapacity = capacity;
    }
    if (registration !== undefined) {
        newRegistration = registration;
    }

    try {
        const entity = {
            key: datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)]),
            data: {
                type: newType,
                capacity: newCapacity,
                registration: newRegistration,
                cans: newCans,
                owner: newOwner,
                self: newSelf,
            }
        }
        await datastore.update(entity);
        res.status(200).json({
            id: parseInt(req.params.aircraft_id, 10),
            type: type,
            capacity: capacity,
            registration: registration,
            cans: newCans,
            owner: newOwner,
            self: newSelf,
        });

    }
    catch (error) {
        res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
    }
})

// Return Status for DELETE all aircraft
app.delete('/aircraft', async (req, res) => {
    return res.status(405).json({ 'Error': 'Deleting the entire list of aircraft is not supported!' });
})

// Delete an Aircraft (DELETE)
app.delete('/aircraft/:aircraft_id', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    try {
        const aircraftId = parseInt(req.params.aircraft_id, 10);
        const aircraftKey = datastore.key(['Aircraft', aircraftId]);
        const [aircraftEntity] = await datastore.get(aircraftKey);

        if (!aircraftEntity) {
            return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
        }

        // Check if sub matches with aircraft owner
        if (sub !== aircraftEntity.owner) {
            return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
        }

        // Find any cans currently on the aircraft and unassign them
        for (let i = 0; i < aircraftEntity.cans.length; i++) {
            try {
                const canKey = datastore.key(['Cans', aircraftEntity.cans[i].id]);
                const [canEntity] = await datastore.get(canKey);

                // Update can
                const updateCanEntity = {
                    key: datastore.key(['Cans', aircraftEntity.cans[i].id]),
                    data: {
                        type: canEntity.type,
                        weight: canEntity.weight,
                        destination: canEntity.destination,
                        carrier: null,
                        self: canEntity.self,
                    }
                }
                await datastore.update(updateCanEntity);

            }
            catch (error) {
                return res.status(400).json({ 'Error': 'An error occurred while deleting the aircraft' });
            }
        }

        // Delete the aircraft
        await datastore.delete(aircraftKey);

        return res.status(204).json();

    } catch (error) {
        console.error('Error:', error);
        return res.status(400).json({ 'Error': 'An error occurred while deleting the aircraft' });
    }
});

// Assign a Can to an Aircraft (PUT)
app.put('/aircraft/:aircraft_id/cans/:can_id', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    // Check if aircraft and can exist from ids
    const queryCan = datastore.createQuery('Cans').filter(new PropertyFilter('__key__', '=', datastore.key(['Cans', parseInt(req.params.can_id, 10)])));
    const [canEntity] = await datastore.runQuery(queryCan);
    const queryAircraft = datastore.createQuery('Aircraft').filter(new PropertyFilter('__key__', '=', datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)])));
    const [aircraftEntity] = await datastore.runQuery(queryAircraft);

    if (canEntity.length <= 0 || aircraftEntity.length <= 0) {
        return res.status(404).json({ 'Error': 'The specified aircraft and/or can do not exist' });
    }

    // Check if sub matches with aircraft owner
    else if (sub !== aircraftEntity[0].owner) {
        return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
    }

    // Check if can is present on a different aircraft
    if (canEntity[0].carrier !== null) {
        return res.status(403).json({ 'Error': 'The can is already on another aircraft' });
    }

    else {
        try {

            // Data to append to cans property
            cansPropertyData = {
                id: parseInt(req.params.can_id, 10),
                self: canEntity[0].self,
            }

            // Append can to the cans property
            aircraftEntity[0].cans.push(cansPropertyData);

            // Update aircraft
            const updateAircraftEntity = {
                key: datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)]),
                data: {
                    type: aircraftEntity[0].type,
                    capacity: aircraftEntity[0].capacity,
                    registration: aircraftEntity[0].registration,
                    cans: aircraftEntity[0].cans,
                    owner: aircraftEntity[0].owner,
                    self: aircraftEntity[0].self,
                }
            }
            await datastore.update(updateAircraftEntity);

            // Data to append to carrier property
            carrierPropertyData = {
                id: parseInt(req.params.aircraft_id, 10),
                name: aircraftEntity[0].name,
                self: aircraftEntity[0].self,
            }

            // Update can
            const updateCanEntity = {
                key: datastore.key(['Cans', parseInt(req.params.can_id, 10)]),
                data: {
                    type: canEntity[0].type,
                    weight: canEntity[0].weight,
                    destination: canEntity[0].destination,
                    carrier: carrierPropertyData,
                    self: canEntity[0].self,
                }
            }
            await datastore.update(updateCanEntity);

            return res.status(204).json();
        }
        catch (error) {
            return res.status(400).json({ error: error.message })
        }

    }

})

// Remove a Can from an Aircraft (DELETE)
app.delete('/aircraft/:aircraft_id/cans/:can_id', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    // Check if aircraft and can exist from ids
    const queryCan = datastore.createQuery('Cans').filter(new PropertyFilter('__key__', '=', datastore.key(['Cans', parseInt(req.params.can_id, 10)])));
    const [canEntity] = await datastore.runQuery(queryCan);
    const queryAircraft = datastore.createQuery('Aircraft').filter(new PropertyFilter('__key__', '=', datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)])));
    const [aircraftEntity] = await datastore.runQuery(queryAircraft);

    if (canEntity.length <= 0 || aircraftEntity.length <= 0) {
        return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id is loaded with the can with this can_id' });
    }

    // Check if sub matches with aircraft owner
    if (sub !== aircraftEntity[0].owner) {
        return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
    }

    else {
        try {

            // Remove data from cans property
            const canIndex = aircraftEntity[0].cans.findIndex(can => can.id === parseInt(req.params.can_id, 10));

            if (canIndex === -1) {
                return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id is loaded with the can with this can_id' });
            }

            aircraftEntity[0].cans.splice(canIndex, 1);

            // Update aircraft
            const updateAircraftEntity = {
                key: datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)]),
                data: {
                    type: aircraftEntity[0].type,
                    capacity: aircraftEntity[0].capacity,
                    registration: aircraftEntity[0].registration,
                    cans: aircraftEntity[0].cans,
                    owner: aircraftEntity[0].owner,
                    self: aircraftEntity[0].self,
                }
            }
            await datastore.update(updateAircraftEntity);

            // Remove data from carrier property
            carrierPropertyData = null

            // Update can
            const updateCanEntity = {
                key: datastore.key(['Cans', parseInt(req.params.can_id, 10)]),
                data: {
                    type: canEntity[0].type,
                    weight: canEntity[0].weight,
                    destination: canEntity[0].destination,
                    carrier: carrierPropertyData,
                    self: canEntity[0].self,
                }
            }
            await datastore.update(updateCanEntity);

            return res.status(204).json();
        }
        catch (error) {
            return res.status(400).json({ error: error.message })
        }

    }

})

// --------------------------------------------------------------------------

// Create a Can (POST)
app.post('/cans', async (req, res) => {
    const { type, weight, destination } = req.body;
    if (type !== undefined && weight !== undefined && destination !== undefined) {


        if (typeof (type) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }


        if (typeof (weight) !== 'number') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }

        if (typeof (destination) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }

        try {
            const canEntity = {
                key: datastore.key('Cans'),
                data: {
                    type: type,
                    weight: weight,
                    destination: destination,
                    carrier: null,
                }
            }

            await datastore.upsert(canEntity)

            const id = canEntity.key.id;
            canEntity.data.self = `${app_url}/cans/${id}`;

            await datastore.upsert(canEntity)

            res.status(201).json({
                id: parseInt(id),
                type: type,
                weight: weight,
                destination: destination,
                carrier: canEntity.data.carrier,
                self: canEntity.data.self,
            });

        }
        catch (error) {
            res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' });
        }
    }
    else {
        res.status(400).json({ 'Error': 'The request object is missing at least one of the required attributes' })
    }
})

// Get a can (GET)
app.get('/cans/:can_id', async (req, res) => {
    try {
        const query = datastore.createQuery('Cans').filter(new PropertyFilter('__key__', '=', datastore.key(['Cans', parseInt(req.params.can_id, 10)])));
        const [entity] = await datastore.runQuery(query);

        if (entity.length > 0) {
            const canData = {
                id: parseInt(req.params.can_id, 10),
                type: entity[0].type,
                weight: entity[0].weight,
                destination: entity[0].destination,
                carrier: entity[0].carrier,
                self: entity[0].self,
            }
            res.status(200).json(canData);
        }
        else {
            res.status(404).json({ 'Error': 'No can with this can_id exists' })
        }

    } catch (error) {
        res.status(404).json({ 'Error': 'No can with this can_id exists' });
    }
})

// List all Cans (GET)
app.get('/cans', async (req, res) => {
    try {

        // Grab query params for offset from url
        const limitParam = parseInt(req.query.limit);
        const offsetParam = parseInt(req.query.page);

        let limit = 5
        if (!isNaN(limitParam)) {
            limit = limitParam
        }

        let offset = 0
        if (!isNaN(offsetParam)) {
            offset = (offsetParam - 1) * limit
        }

        // Generate link for next page
        let newOffset = null;
        if (offsetParam === 0 || isNaN(offsetParam)) {
            newOffset = 2;
        } else {
            newOffset = offsetParam + 1;
        }
        let nextPageLink = `/cans/?limit=${limit}&page=${newOffset}`

        const query = datastore.createQuery('Cans').limit(limit).offset(offset);
        const [entities] = await datastore.runQuery(query);

        // Check if this is the last page
        const queryNext = datastore.createQuery('Cans').limit(limit).offset(offset + limit)
        const [nextEntity] = await datastore.runQuery(queryNext);
        if (nextEntity.length <= 0) {
            nextPageLink = null;
        }

        if (nextPageLink !== null) {
            cansData = {
                offset: offset,
                limit: limit,
                cans: [],
                next: nextPageLink,
            }
        } else (
            cansData = {
                offset: offset,
                limit: limit,
                cans: [],
            }
        )

        if (entities.length > 0) {
            for (i = 0; i < entities.length; i++) {
                dataForCan = {
                    id: entities[i][datastore.KEY].id,
                    type: entities[i].type,
                    weight: entities[i].weight,
                    destination: entities[i].destination,
                    carrier: entities[i].carrier,
                    self: entities[i].self,
                }
                cansData.cans.push(dataForCan);
            }
        }

        return res.status(200).json(cansData);
    }
    catch (error) {
        return res.status(404).json({ error: error.message });
    }
})

// View all Cans for a given Aircraft
app.get('/aircraft/:aircraft_id/cans', async (req, res) => {

    // Check for valid JWT belonging to aircraft owner
    const headers = req.headers.authorization

    if (!headers) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    const token = req.headers.authorization.substring('Bearer '.length);

    const jwksURI = `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`;

    let sub = null;

    try {
        const jwks = await axios.get(jwksURI);
        const decodedToken = jwt.decode(token, { complete: true });

        sub = decodedToken.payload.sub;

        const kid = decodedToken.header.kid;

        const signingKey = jwks.data.keys.find((key) => key.kid === kid);

        if (!signingKey) {
            return res.send({ 'Error': 'Unable to find matching key in JWKS' });
        }

        const publicKey = `-----BEGIN CERTIFICATE-----\n${signingKey.x5c[0]}\n-----END CERTIFICATE-----`;

        const verifyOptions = {
            algorithms: ['RS256'],
        };

        jwt.verify(token, publicKey, verifyOptions);


    } catch (error) {
        return res.status(401).json({ 'Error': 'Token verification failed' });
    }

    try {
        const query = datastore.createQuery('Aircraft').filter(new PropertyFilter('__key__', '=', datastore.key(['Aircraft', parseInt(req.params.aircraft_id, 10)])));
        const [entity] = await datastore.runQuery(query);

        // Check if sub matches with aircraft owner
        if (sub !== entity[0].owner) {
            return res.status(401).json({ 'Error': 'Not authorized to modify or view this element' })
        }

        cansData = {
            cans: [],
        }

        if (entity.length > 0) {
            for (i = 0; i < entity[0].cans.length; i++) {

                const canQuery = datastore.createQuery('Cans').filter(new PropertyFilter('__key__', '=', datastore.key(['Cans', entity[0].cans[i].id])));
                const [canEntity] = await datastore.runQuery(canQuery);

                if (canEntity.length > 0) {
                    // Data for can
                    dataForCan = {
                        id: canEntity[0][datastore.KEY].id,
                        type: canEntity[0].type,
                        weight: canEntity[0].weight,
                        destination: canEntity[0].destination,
                        self: canEntity[0].self,
                    }

                }

                cansData.cans.push(dataForCan);

            }

            return res.status(200).json(cansData);
        }
        else {
            return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
        }

    } catch (error) {
        return res.status(404).json({ 'Error': 'No aircraft with this aircraft_id exists' });
    }
})

// Edit a Can (PATCH)
app.patch('/cans/:can_id', async (req, res) => {
    const { type, weight, destination } = req.body;

    // Check for invalid Accept header MIME type
    if (req.headers['accept'] !== '*/*' && !req.headers['accept'].includes('application/json')) {
        return res.status(406).json({ 'Error': 'Endpoint does not support that MIME type for header Accept (supported types: applications/json)' })
    }

    // Check for invalid Content-Type header MIME type
    if (req.headers['content-type'] !== '*/*' && !req.headers['content-type'].includes('application/json')) {
        return res.status(415).json({ 'Error': 'Endpoint does not support that MIME type for header Content-Type (supported types: applications/json)' })
    }

    if (type !== undefined) {
        if (typeof (type) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    if (weight !== undefined) {
        if (typeof (weight) !== 'number') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    if (destination !== undefined) {
        if (typeof (destination) !== 'string') {
            return res.status(400).json({ 'Error': 'The request object contains an invalid data type' })
        }
    }

    // Query the current information for the can
    const query = datastore.createQuery('Cans').filter(new PropertyFilter('__key__', '=', datastore.key(['Cans', parseInt(req.params.can_id, 10)])));
    const [entity] = await datastore.runQuery(query);

    if (entity.length < 1) {
        return res.status(404).json({ 'Error': 'No can with this can_id exists' });
    }

    let newType = entity[0].type;
    let newWeight = entity[0].weight;
    let newDestination = entity[0].destination;
    let newCarrier = entity[0].carrier;
    let newSelf = entity[0].self;

    if (type !== undefined) {
        newType = type;
    }
    if (weight !== undefined) {
        newWeight = weight;
    }
    if (destination !== undefined) {
        newDestination = destination;
    }

    try {
        const entity = {
            key: datastore.key(['Cans', parseInt(req.params.can_id, 10)]),
            data: {
                type: newType,
                weight: newWeight,
                destination: newDestination,
                carrier: newCarrier,
                self: newSelf,
            }
        }
        await datastore.update(entity);
        res.status(200).json({
            id: parseInt(req.params.can_id, 10),
            type: newType,
            weight: newWeight,
            destination: newDestination,
            carrier: newCarrier,
            self: newSelf,
        });

    }
    catch (error) {
        res.status(404).json({ 'Error': 'No can with this can_id exists' });
    }
})

// Return Status for DELETE all cans
app.delete('/cans', async (req, res) => {
    return res.status(405).json({ 'Error': 'Deleting the entire list of cans is not supported!' });
})

// Delete a Can (DELETE)
app.delete('/cans/:can_id', async (req, res) => {
    try {
        const canId = parseInt(req.params.can_id, 10);
        const canKey = datastore.key(['Cans', canId]);

        // Check if the can exists
        const [entity] = await datastore.get(canKey);

        if (!entity) {
            return res.status(404).json({ 'Error': 'No can with this can_id exists' });
        }

        // Check if the can has a carrier
        if (entity.carrier && entity.carrier.id !== null) {
            // Find the aircraft that carries the can
            const aircraftKey = datastore.key(['Aircraft', entity.carrier.id]);
            const [aircraftEntity] = await datastore.get(aircraftKey);

            if (aircraftEntity) {
                // Remove the can from the aircraft's cans array
                const canIndex = aircraftEntity.cans.findIndex(can => can.id === canId);

                if (canIndex !== -1) {
                    aircraftEntity.cans.splice(canIndex, 1);

                    // Update the aircraft
                    const updateAircraftEntity = {
                        key: aircraftKey,
                        data: {
                            type: aircraftEntity.type,
                            capacity: aircraftEntity.capacity,
                            registration: aircraftEntity.registration,
                            cans: aircraftEntity.cans,
                            owner: aircraftEntity.owner,
                            self: aircraftEntity.self,
                        }
                    }
                    await datastore.update(updateAircraftEntity);
                }
            }
        }

        // Delete the can
        await datastore.delete(canKey);

        res.status(204).json();
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --------------------------------------------------------------------------

// View a user profile
app.get('/users/:user_id', async (req, res) => {

    // Check for invalid Accept header MIME type
    if (req.headers['accept'] && req.headers['accept'] !== '*/*' && !req.headers['accept'].includes('application/json') && !req.headers['accept'].includes('text/html')) {
        return res.status(406).json({ 'Error': 'Endpoint does not support that MIME type for header Accept (supported types: application/json)' });
    }

    // Check for invalid Content-Type header MIME type
    if (req.headers['content-type'] && req.headers['content-type'] !== '*/*' && !req.headers['content-type'].includes('application/json') && !req.headers['content-type'].includes('text/html')) {
        return res.status(415).json({ 'Error': 'Endpoint does not support that MIME type for header Content-Type (supported types: application/json)' });
    }

    try {
        const query = datastore.createQuery('Users').filter(new PropertyFilter('__key__', '=', datastore.key(['Users', req.params.user_id])));
        const [entity] = await datastore.runQuery(query);

        if (entity.length > 0) {
            const userData = {
                email: entity[0].email,
                time_created: entity[0].time_created,
                sub: entity[0].sub
            }

            // Return with HTML
            if (req.headers['accept'] === 'text/html') {
                return res.status(200).send(`<html><ul><li>Email: ${userData.email}</li><li>Time Created: ${userData.time_created}</li><li>sub: ${userData.sub}</li></ul></html>`);
            }

            // Return with json (default)
            else {
                return res.status(200).json(userData);
            }

        }
        else {
            res.status(404).json({ 'Error': 'No user with this user_id exists' })
        }

    } catch (error) {
        res.status(404).json({ 'Error': error });
    }
})

// List all Users (GET)
app.get('/users', async (req, res) => {
    try {

        // Grab query params for offset from url
        const limitParam = parseInt(req.query.limit);
        const offsetParam = parseInt(req.query.page);

        let limit = 5
        if (!isNaN(limitParam)) {
            limit = limitParam
        }

        let offset = 0
        if (!isNaN(offsetParam)) {
            offset = (offsetParam - 1) * limit
        }

        // Generate link for next page
        let newOffset = null;
        if (offsetParam === 0 || isNaN(offsetParam)) {
            newOffset = 2;
        } else {
            newOffset = offsetParam + 1;
        }
        let nextPageLink = `/users/?limit=${limit}&page=${newOffset}`

        const query = datastore.createQuery('Users').limit(limit).offset(offset);
        const [entities] = await datastore.runQuery(query);

        // Check if this is the last page
        const queryNext = datastore.createQuery('Users').limit(limit).offset(offset + limit)
        const [nextEntity] = await datastore.runQuery(queryNext);
        if (nextEntity.length <= 0) {
            nextPageLink = null;
        }

        if (nextPageLink !== null) {
            usersData = {
                offset: offset,
                limit: limit,
                users: [],
                next: nextPageLink,
            }
        } else {
            usersData = {
                offset: offset,
                limit: limit,
                users: [],
            }
        }

        if (entities.length > 0) {
            for (i = 0; i < entities.length; i++) {
                dataForUser = {
                    id: entities[i][datastore.KEY].name,
                    email: entities[i].email,
                    time_created: entities[i].time_created,
                    sub: entities[i].sub,
                }
                usersData.users.push(dataForUser);
            }
        }

        return res.status(200).json(usersData);
    }
    catch (error) {
        return res.status(404).json({ error: error.message });
    }
})